use std::marker::PhantomData;

use alloy_consensus::{private::alloy_eips::BlockNumberOrTag, Header};
use alloy_primitives::{map::HashMap, Address, Bytes, B256};
use alloy_provider::{ext::DebugApi, Network, Provider};
use alloy_rlp::Decodable;
use alloy_trie::TrieAccount;
use async_trait::async_trait;
use mpt::EthereumState;
use reth_storage_errors::ProviderError;
use revm_database::{BundleState, DatabaseRef};
use revm_primitives::{keccak256, ruint::aliases::U256, StorageKey, StorageValue};
use revm_state::{AccountInfo, Bytecode};
use serde::{Deserialize, Serialize};

use crate::{RpcDb, RpcDbError};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWitnessGoat {
    pub state: Vec<Bytes>,
    pub codes: Vec<Bytes>,
    pub keys: Option<Vec<Bytes>>,
    pub headers: Vec<Header>,
}

#[derive(Debug)]
pub struct ExecutionWitnessRpcDb<P, N> {
    /// The provider which fetches data.
    pub provider: P,
    /// The cached state.
    pub state: EthereumState,
    /// The cached bytecodes.
    pub codes: HashMap<B256, Bytecode>,

    pub ancestor_headers: HashMap<u64, Header>,

    phantom: PhantomData<N>,
}

impl<P: Provider<N> + Clone, N: Network> ExecutionWitnessRpcDb<P, N> {
    /// Create a new [`ExecutionWitnessRpcDb`].
    pub async fn new(
        provider: P,
        block_number: u64,
        state_root: B256,
        is_goat_testnet: bool,
    ) -> Result<Self, RpcDbError> {
        let (state, codes, headers) = if is_goat_testnet {
            let execution_witness: ExecutionWitnessGoat = provider
                .raw_request(
                    "debug_executionWitness".into(),
                    (BlockNumberOrTag::Number(block_number + 1),),
                )
                .await?;

            (execution_witness.state, execution_witness.codes, execution_witness.headers)
        } else {
            let execution_witness =
                provider.debug_execution_witness((block_number + 1).into()).await?;
            let headers = execution_witness
                .headers
                .iter()
                .map(|encoded| Header::decode(&mut encoded.as_ref()).unwrap())
                .collect();

            (execution_witness.state, execution_witness.codes, headers)
        };
        tracing::info!("fetch execution witness for block {}", block_number + 1);

        let state = EthereumState::from_execution_witness(&state, state_root);
        let codes = codes
            .into_iter()
            .map(|encoded| (keccak256(&encoded), Bytecode::new_raw(encoded)))
            .collect();
        let ancestor_headers = headers.into_iter().map(|h| (h.number, h)).collect();

        let db = Self { provider, state, codes, ancestor_headers, phantom: PhantomData };

        Ok(db)
    }
}

impl<P: Provider<N> + Clone, N: Network> DatabaseRef for ExecutionWitnessRpcDb<P, N> {
    type Error = ProviderError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let hash = keccak256(address);
        if let Some(mut bytes) = self
            .state
            .state_trie
            .get(hash.as_ref())
            .map_err(|err| ProviderError::TrieWitnessError(err.to_string()))?
        {
            let account = TrieAccount::decode(&mut bytes)?;
            let account_info = AccountInfo {
                balance: account.balance,
                nonce: account.nonce,
                code_hash: account.code_hash,
                code: None,
            };

            Ok(Some(account_info))
        } else {
            Ok(None)
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.codes
            .get(&code_hash)
            .ok_or_else(|| {
                ProviderError::TrieWitnessError(format!("Code not found for {code_hash}"))
            })
            .cloned()
    }

    fn storage_ref(
        &self,
        address: Address,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        let slot = B256::from(index);
        let hashed_address = keccak256(address);
        let hashed_slot = keccak256(slot);
        if let Some(mut value) = self
            .state
            .storage_tries
            .get(&hashed_address)
            .and_then(|storage_trie| storage_trie.get(hashed_slot.as_slice()).unwrap())
        {
            Ok(U256::decode(&mut value)?)
        } else {
            Ok(U256::ZERO)
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let header = self.ancestor_headers.get(&number).ok_or_else(|| {
            ProviderError::TrieWitnessError(format!("Header {number} not found in the ancestors"))
        })?;

        Ok(header.hash_slow())
    }
}

#[async_trait]
impl<P, N> RpcDb<N> for ExecutionWitnessRpcDb<P, N>
where
    P: Provider<N> + Clone,
    N: Network,
{
    async fn state(&self, _bundle_state: &BundleState) -> Result<EthereumState, RpcDbError> {
        Ok(self.state.clone())
    }

    fn bytecodes(&self) -> Vec<Bytecode> {
        self.codes.values().cloned().collect()
    }

    async fn ancestor_headers(&self) -> Result<Vec<Header>, RpcDbError> {
        let mut ancestor_headers: Vec<Header> = self.ancestor_headers.values().cloned().collect();
        ancestor_headers.sort_by(|a, b| b.number.cmp(&a.number));
        Ok(ancestor_headers)
    }
}
