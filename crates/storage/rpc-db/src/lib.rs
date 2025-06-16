#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_primitives::{map::HashMap, private::serde::Deserialize, Bytes, U256};
use alloy_provider::{
    network::{primitives::HeaderResponse, BlockResponse},
    Network, Provider,
};
use alloy_rpc_types::{Block, BlockId};
use indexmap::IndexMap;
use reth_storage_errors::{db::DatabaseError, provider::ProviderError};
use revm_database_interface::DatabaseRef;
use revm_primitives::{Address, B256};
use revm_state::{AccountInfo, Bytecode};
use std::{borrow::Cow, collections::{BTreeMap, BTreeSet}, fs, marker::PhantomData, sync::{Arc, RwLock}};
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;
use tracing::{debug, info};

/// A database that fetches data from a [Provider] over a [Transport].
#[derive(Debug, Clone)]
pub struct RpcDb<P, N> {
    /// The provider which fetches data.
    pub provider: P,
    /// The provider which fetches debug info.
    pub debug_provider: P,
    /// The block to fetch data from.
    pub block: BlockId,
    /// The cached accounts.
    pub accounts: Arc<RwLock<HashMap<Address, AccountInfo>>>,
    /// The cached storage values.
    pub storage: Arc<RwLock<HashMap<Address, HashMap<U256, U256>>>>,
    /// The oldest block whose header/hash has been requested.
    pub oldest_ancestor: Arc<RwLock<u64>>,

    phantom: std::marker::PhantomData<N>,
}

/// Top-level RPC response from debug_traceBlockByNumber with prestate enabled
#[derive(Debug, Clone, Deserialize)]
pub struct PrestateTraceRpcResponse(pub Vec<PrestateTxTrace>);

/// A single transaction's trace prestate result
#[derive(Debug, Clone, Deserialize)]
pub struct PrestateTxTrace {
    /// Transaction hash
    #[serde(rename = "txHash")]
    pub tx_hash: B256,

    /// Mapping of address -> account info (preserves insertion order)
    pub result: IndexMap<Address, PrestateAccount>,
}

/// An account's state at the start of the transaction execution
#[derive(Debug, Clone, Deserialize)]
pub struct PrestateAccount {
    /// Account balance
    pub balance: Option<U256>,

    /// Account nonce
    pub nonce: Option<u64>,

    /// Account code, if present
    pub code: Option<Bytes>,

    /// Optional storage slot mapping
    pub storage: Option<IndexMap<U256, U256>>,
}

/// Errors that can occur when interacting with the [RpcDb].
#[derive(Debug, Clone, thiserror::Error)]
pub enum RpcDbError {
    #[error("failed fetch proof at {0}: {1}")]
    GetProofError(Address, String),
    #[error("failed to fetch code at {0}: {1}")]
    GetCodeError(Address, String),
    #[error("failed to fetch storage at {0}, index {1}: {2}")]
    GetStorageError(Address, U256, String),
    #[error("failed to fetch block {0}: {1}")]
    GetBlockError(u64, String),
    #[error("failed to find block")]
    BlockNotFound,
    #[error("failed to find trie node preimage")]
    PreimageNotFound,
    #[error("poisoned lock")]
    Poisoned,
}

impl<P: Provider<N> + Clone, N: Network> RpcDb<P, N> {
    /// Create a new [`RpcDb`].
    pub fn new(provider: P, debug_provider: P, block: u64) -> Self {
        RpcDb {
            provider,
            debug_provider,
            block: block.into(),
            accounts: Arc::new(RwLock::new(HashMap::with_hasher(Default::default()))),
            storage: Arc::new(RwLock::new(HashMap::with_hasher(Default::default()))),
            oldest_ancestor: Arc::new(RwLock::new(block)),
            phantom: PhantomData,
        }
    }

    /// Fetch the [AccountInfo] for an [Address].
    pub async fn fetch_account_info(&self, address: Address) -> Result<AccountInfo, RpcDbError> {
        debug!("fetching account info for address: {}", address);
        if let Some(account_info) =
            self.accounts.read().map_err(|_| RpcDbError::Poisoned)?.get(&address).cloned()
        {
            debug!("fetching account info from cache for address: {}", address);
            return Ok(account_info);
        }

        // Fetch the proof for the account.
        let proof = self
            .provider
            .get_proof(address, vec![])
            .block_id(self.block)
            .await
            .map_err(|e| RpcDbError::GetProofError(address, e.to_string()))?;

        // Fetch the code of the account.
        let code = self
            .provider
            .get_code_at(address)
            .block_id(self.block)
            .await
            .map_err(|e| RpcDbError::GetCodeError(address, e.to_string()))?;

        // Construct the account info & write it to the log.
        let bytecode = Bytecode::new_raw(code);
        let account_info = AccountInfo {
            nonce: proof.nonce,
            balance: proof.balance,
            code_hash: proof.code_hash,
            code: Some(bytecode.clone()),
        };
        debug!(
            "[fetch_account_info]fetching basic account info for address: {}, balance: {:?}, nonce: {:?}, code_hash: {:?}",
            address, account_info.balance, account_info.nonce, account_info.code_hash
        );

        // Record the account info to the state.
        self.accounts
            .write()
            .map_err(|_| RpcDbError::Poisoned)?
            .insert(address, account_info.clone());

        Ok(account_info)
    }

    /// Fetch the storage value at an [Address] and [U256] index.
    pub async fn fetch_storage_at(
        &self,
        address: Address,
        index: U256,
    ) -> Result<U256, RpcDbError> {
        debug!("fetching storage value at address: {}, index: {}", address, index);
        if let Some(value) = self
            .storage
            .read()
            .map_err(|_| RpcDbError::Poisoned)?
            .get(&address)
            .and_then(|inner| inner.get(&index).copied())
        {
            debug!("fetching account info from cache for address {}, index {:x}, value {}", address, index, value);
            return Ok(value);
        }

        // Fetch the storage value.
        let value = self
            .provider
            .get_storage_at(address, index)
            .block_id(self.block)
            .await
            .map_err(|e| RpcDbError::GetStorageError(address, index, e.to_string()))?;
        debug!("[fetch_storage_at] fetching storage value at address: {}, index: {}, value {}", address, index, value);

        // Record the storage value to the state.
        let mut storage_values = self.storage.write().map_err(|_| RpcDbError::Poisoned)?;
        let entry = storage_values.entry(address).or_default();
        entry.insert(index, value);

        Ok(value)
    }

    /// Fetch the block hash for a block number.
    pub async fn fetch_block_hash(&self, number: u64) -> Result<B256, RpcDbError> {
        debug!("fetching block hash for block number: {}", number);

        // Fetch the block.
        let block = self
            .provider
            .get_block_by_number(number.into())
            .await
            .map_err(|e| RpcDbError::GetBlockError(number, e.to_string()))?;

        // Record the block hash to the state.
        let block = block.ok_or(RpcDbError::BlockNotFound)?;
        let hash = block.header().hash();

        let mut oldest_ancestor = self.oldest_ancestor.write().map_err(|_| RpcDbError::Poisoned)?;
        *oldest_ancestor = number.min(*oldest_ancestor);

        Ok(hash)
    }

    /// Preloads accounts and storage for the current block.
    ///  We use debug_provider.
    pub async fn preload_accounts_and_storage(&self) -> Result<(), RpcDbError> {
        info!(
            "Preloading accounts and storage for block: {}",
            self.block
        );
        let current_block = self.block.as_u64().unwrap() + 1;
        let params = (
            format!("0x{:x}", current_block),
            serde_json::json!({
                "disableStorage": false,
                "disableMemory": true,
                "disableStack": true,
                "tracer": "prestateTracer"
            }),
        );

        let now = std::time::Instant::now();
        // TODO: use debug_traceTransaction in parallel instead of debug_traceBlockByNumber
        let prestate: PrestateTraceRpcResponse = self
            .debug_provider
            .raw_request("debug_traceBlockByNumber".into(), params)
            .await
            .map_err(|e| {
                RpcDbError::GetBlockError(current_block, e.to_string())
            })?;
        info!("rpc request took: {:?}, got {} txs", now.elapsed(),prestate.0.len());

        for tx_trace in prestate.0 {
            for (address, account) in tx_trace.result {
                if !self.accounts.read().map_err(|_| RpcDbError::Poisoned)?.contains_key(&address) {
                    let bytecode = account.code.clone().map(Bytecode::new_raw);
                    /// Some RPC will return incorrect code and nonce for accounts with EIP-7702,
                    /// we will ignore these accounts.
                    /// This is a temporary fix
                    if bytecode.as_ref().is_some_and(|bc| bc.is_eip7702()) {
                        continue;
                    }

                    let account_info = AccountInfo::from_bytecode(bytecode.unwrap_or_default())
                        .with_balance(account.balance.unwrap_or_default())
                        .with_nonce(account.nonce.unwrap_or_default());

                    self.accounts
                        .write()
                        .map_err(|_| RpcDbError::Poisoned)?
                        .entry(address)
                        .or_insert(account_info);
                }

                if let Some(storage_map) = account.storage {
                    let mut storage_lock =
                        self.storage.write().map_err(|_| RpcDbError::Poisoned)?;
                    let account_storage = storage_lock.entry(address).or_insert_with(|| HashMap::with_hasher(Default::default()));

                    for (slot, value) in storage_map {
                        account_storage.entry(slot).or_insert(value);
                    }
                }
            }
        }
        Ok(())
    }

    /// Gets all the state keys used. The client uses this to read the actual state data from tries.
    pub fn get_state_requests(&self) -> HashMap<Address, Vec<U256>> {
        let accounts = self.accounts.read().unwrap();
        let storage = self.storage.read().unwrap();

        accounts
            .keys()
            .chain(storage.keys())
            .map(|&address| {
                let storage_keys_for_address: BTreeSet<U256> = storage
                    .get(&address)
                    .map(|storage_map| storage_map.keys().cloned().collect())
                    .unwrap_or_default();

                (address, storage_keys_for_address.into_iter().collect())
            })
            .collect()
    }

    /// Gets all account bytecodes.
    pub fn get_bytecodes(&self) -> Vec<Bytecode> {
        let accounts = self.accounts.read().unwrap();

        accounts
            .values()
            .flat_map(|account| account.code.clone())
            .map(|code| (code.hash_slow(), code))
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .collect::<Vec<_>>()
    }
}

impl<P: Provider<N> + Clone, N: Network> DatabaseRef for RpcDb<P, N> {
    type Error = ProviderError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            ProviderError::Database(DatabaseError::Other("no tokio runtime found".to_string()))
        })?;
        let result =
            tokio::task::block_in_place(|| handle.block_on(self.fetch_account_info(address)));
        let account_info =
            result.map_err(|e| ProviderError::Database(DatabaseError::Other(e.to_string())))?;
        Ok(Some(account_info))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        unimplemented!()
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            ProviderError::Database(DatabaseError::Other("no tokio runtime found".to_string()))
        })?;
        let result =
            tokio::task::block_in_place(|| handle.block_on(self.fetch_storage_at(address, index)));
        let value =
            result.map_err(|e| ProviderError::Database(DatabaseError::Other(e.to_string())))?;
        Ok(value)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            ProviderError::Database(DatabaseError::Other("no tokio runtime found".to_string()))
        })?;
        let result = tokio::task::block_in_place(|| handle.block_on(self.fetch_block_hash(number)));
        let value =
            result.map_err(|e| ProviderError::Database(DatabaseError::Other(e.to_string())))?;
        Ok(value)
    }
}
