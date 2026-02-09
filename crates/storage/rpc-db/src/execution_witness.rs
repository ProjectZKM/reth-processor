use std::{marker::PhantomData, sync::RwLock};

use crate::{RpcDb, RpcDbError};
use alloy_consensus::{private::alloy_eips::BlockNumberOrTag, Header};
use alloy_primitives::{map::HashMap, Address, Bytes, B256};
use alloy_provider::{ext::DebugApi, Network, Provider};
use alloy_rlp::Decodable;
use alloy_trie::TrieAccount;
use async_trait::async_trait;
use mpt::EthereumState;
use primitives::is_precompile;
use reth_storage_errors::ProviderError;
use revm_database::{BundleState, DatabaseRef};
use revm_primitives::{keccak256, ruint::aliases::U256, StorageKey, StorageValue};
use revm_state::{AccountInfo, Bytecode};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWitnessGoat {
    pub state: Vec<Bytes>,
    pub codes: Vec<Bytes>,
    pub keys: Option<Vec<Bytes>>,
    pub headers: Vec<Header>,
}

pub struct ExecutionWitnessRpcDb<P, N> {
    /// The provider which fetches data.
    pub provider: P,
    /// The cached state (may be incomplete for fallback accounts).
    pub state: EthereumState,
    /// The cached bytecodes.
    pub codes: HashMap<B256, Bytecode>,
    /// Ancestor headers for BLOCKHASH opcode.
    pub ancestor_headers: HashMap<u64, Header>,
    /// The parent block number (for RPC fallback queries).
    parent_block_number: u64,
    /// The state root used to build the EthereumState.
    state_root: B256,
    /// The original witness state nodes (for rebuilding with additional proofs).
    raw_state_nodes: Vec<Bytes>,
    /// Addresses that needed RPC fallback due to incomplete witness.
    fallback_addresses: RwLock<Vec<Address>>,

    phantom: PhantomData<N>,
}

impl<P: std::fmt::Debug, N> std::fmt::Debug for ExecutionWitnessRpcDb<P, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionWitnessRpcDb")
            .field("provider", &self.provider)
            .field("state", &self.state)
            .field("codes", &self.codes)
            .field("ancestor_headers", &self.ancestor_headers)
            .field("parent_block_number", &self.parent_block_number)
            .field("state_root", &self.state_root)
            .field("raw_state_nodes_len", &self.raw_state_nodes.len())
            .field("fallback_addresses", &*self.fallback_addresses.read().unwrap())
            .finish()
    }
}

impl<P: Provider<N> + Clone, N: Network> ExecutionWitnessRpcDb<P, N> {
    /// Create a new [`ExecutionWitnessRpcDb`].
    pub async fn new(
        provider: P,
        block_number: u64,
        state_root: B256,
        is_goat_testnet: bool,
    ) -> Result<Self, RpcDbError> {
        let (state_nodes, codes, headers) = if is_goat_testnet {
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

        let state = EthereumState::from_execution_witness(&state_nodes, state_root);
        let codes = codes
            .into_iter()
            .map(|encoded| (keccak256(&encoded), Bytecode::new_raw(encoded)))
            .collect();
        let ancestor_headers = headers.into_iter().map(|h| (h.number, h)).collect();

        let db = Self {
            provider,
            state,
            codes,
            ancestor_headers,
            parent_block_number: block_number,
            state_root,
            raw_state_nodes: state_nodes,
            fallback_addresses: RwLock::new(Vec::new()),
            phantom: PhantomData,
        };

        Ok(db)
    }

    /// Fetch account info via RPC when witness data is incomplete.
    /// Records the address for later proof fetching.
    fn fetch_account_via_rpc(&self, address: Address) -> Result<Option<AccountInfo>, ProviderError>
    where
        P: Clone,
    {
        // Use tokio runtime to execute async RPC calls from sync context
        let handle = tokio::runtime::Handle::current();
        let provider = self.provider.clone();
        let block_tag = BlockNumberOrTag::Number(self.parent_block_number);

        let result: Result<(U256, u64, Bytecode), Box<dyn std::error::Error + Send + Sync>> =
            tokio::task::block_in_place(|| {
                handle.block_on(async {
                    // Fetch balance, nonce and code in parallel
                    let balance_fut = provider.get_balance(address).block_id(block_tag.into());
                    let nonce_fut =
                        provider.get_transaction_count(address).block_id(block_tag.into());
                    let code_fut = provider.get_code_at(address).block_id(block_tag.into());

                    let (balance, nonce, code) =
                        tokio::try_join!(balance_fut, nonce_fut, code_fut)?;
                    let bytecode = Bytecode::new_raw(code);

                    Ok((balance, nonce, bytecode))
                })
            });

        match result {
            Ok((balance, nonce, bytecode)) => {
                // Record this address for proof fetching in state()
                self.fallback_addresses.write().unwrap().push(address);

                // If balance, nonce and code are all zero/empty, treat as non-existent
                if balance.is_zero() && nonce == 0 && bytecode.is_empty() {
                    tracing::debug!(
                        "RPC fallback: address {:?} has zero balance, nonce and empty code, treating as non-existent",
                        address
                    );
                    Ok(None)
                } else {
                    let code_hash = bytecode.hash_slow();
                    tracing::debug!(
                        "RPC fallback: address {:?} has balance={}, nonce={}, code_hash={}",
                        address,
                        balance,
                        nonce,
                        code_hash
                    );
                    Ok(Some(AccountInfo { balance, nonce, code_hash, code: Some(bytecode) }))
                }
            }
            Err(err) => {
                tracing::error!("RPC fallback failed for address {:?}: {}", address, err);
                Err(ProviderError::TrieWitnessError(format!("RPC fallback failed: {}", err)))
            }
        }
    }

    /// Fetches proofs for fallback addresses and returns merged state nodes.
    async fn get_merged_state_nodes(&self) -> Result<Vec<Bytes>, RpcDbError>
    where
        P: Clone,
    {
        let fallback_addrs: Vec<Address> = self.fallback_addresses.read().unwrap().clone();

        if fallback_addrs.is_empty() {
            return Ok(self.raw_state_nodes.clone());
        }

        tracing::info!(
            "Fetching proofs for {} fallback addresses to complete witness",
            fallback_addrs.len()
        );

        let block_tag = BlockNumberOrTag::Number(self.parent_block_number);
        let mut merged_nodes = self.raw_state_nodes.clone();

        for address in fallback_addrs {
            // Fetch the account proof via eth_getProof
            let proof = self.provider.get_proof(address, vec![]).block_id(block_tag.into()).await?;

            let node_count = proof.account_proof.len();

            // Add proof nodes to the merged list
            for node in proof.account_proof {
                merged_nodes.push(node);
            }

            tracing::debug!("Added {} proof nodes for address {:?}", node_count, address);
        }

        Ok(merged_nodes)
    }
}

impl<P: Provider<N> + Clone, N: Network> DatabaseRef for ExecutionWitnessRpcDb<P, N> {
    type Error = ProviderError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let hash = keccak256(address);
        match self
            .state
            .state_trie
            .get(hash.as_ref())
            .map_err(|err| ProviderError::TrieWitnessError(err.to_string()))
        {
            Ok(Some(mut bytes)) => {
                let account = TrieAccount::decode(&mut bytes)?;
                let account_info = AccountInfo {
                    balance: account.balance,
                    nonce: account.nonce,
                    code_hash: account.code_hash,
                    code: None,
                };

                Ok(Some(account_info))
            }
            Ok(None) => Ok(None),
            Err(err) => {
                // If the account is a precompile, we can assume it's empty.
                if is_precompile(address) {
                    return Ok(None);
                }
                // WORKAROUND: If the witness is incomplete (NodeNotResolved),
                // fallback to RPC to fetch account info directly.
                if let ProviderError::TrieWitnessError(ref msg) = err {
                    if msg.contains("unresolved node") {
                        tracing::warn!(
                            "Witness incomplete for address {:?}, falling back to RPC",
                            address
                        );
                        return self.fetch_account_via_rpc(address);
                    }
                }
                Err(err)
            }
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
        // Merge original witness nodes with proofs for fallback addresses
        let merged_nodes = self.get_merged_state_nodes().await?;

        // Rebuild EthereumState with complete witness data
        let state = EthereumState::from_execution_witness(&merged_nodes, self.state_root);

        Ok(state)
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
