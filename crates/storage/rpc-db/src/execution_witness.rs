use std::{collections::BTreeMap, marker::PhantomData, sync::RwLock};

use alloy_consensus::Header;
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{map::HashMap, Address, B256};
use alloy_provider::{Network, Provider};
use alloy_rlp::{Decodable, Encodable};
use alloy_rpc_types::Header as RpcHeader;
use alloy_rpc_types_debug::ExecutionWitness;
use alloy_trie::TrieAccount;
use async_trait::async_trait;
use mpt::EthereumState;
use reth_storage_errors::{db::DatabaseError, ProviderError};
use revm_database::{BundleState, DatabaseRef};
use revm_primitives::{keccak256, ruint::aliases::U256, StorageKey, StorageValue, KECCAK_EMPTY};
use revm_state::{AccountInfo, Bytecode};
use serde::Deserialize;

use crate::{RpcDb, RpcDbError};

#[derive(Debug)]
pub struct ExecutionWitnessRpcDb<P, N> {
    /// The provider which fetches data.
    pub provider: P,
    /// Parent block used to fetch bytecode omitted from the execution witness.
    pub state_block_number: u64,
    /// The cached state.
    pub state: EthereumState,
    /// The cached bytecodes.
    pub codes: RwLock<HashMap<B256, Bytecode>>,

    pub ancestor_headers: BTreeMap<u64, Header>,

    phantom: PhantomData<N>,
}

impl<P: Provider<N> + Clone, N: Network> ExecutionWitnessRpcDb<P, N> {
    /// Create a new [`ExecutionWitnessRpcDb`].
    pub async fn new(provider: P, block_number: u64, state_root: B256) -> Result<Self, RpcDbError> {
        tracing::info!("Fetching execution witness for block {}", block_number);
        let execution_witness = fetch_execution_witness(&provider, block_number).await?;
        tracing::info!("Fetched execution witness for block done {}", block_number);

        let state = EthereumState::from_execution_witness(&execution_witness, state_root);

        let codes = execution_witness
            .codes
            .iter()
            .map(|encoded| (keccak256(encoded), Bytecode::new_raw(encoded.clone())))
            .collect();

        let ancestor_headers = execution_witness
            .headers
            .iter()
            .map(|encoded| Header::decode(&mut encoded.as_ref()).unwrap())
            .map(|h| (h.number, h))
            .collect();

        let db = Self {
            provider,
            state_block_number: block_number.saturating_sub(1),
            state,
            codes: RwLock::new(codes),
            ancestor_headers,
            phantom: PhantomData,
        };

        Ok(db)
    }

    fn account_code(
        &self,
        address: Address,
        expected_hash: B256,
    ) -> Result<Option<Bytecode>, ProviderError> {
        if expected_hash == KECCAK_EMPTY || expected_hash == B256::ZERO {
            return Ok(None)
        }
        if let Some(code) = self
            .codes
            .read()
            .map_err(|_| ProviderError::TrieWitnessError("bytecode cache lock poisoned".into()))?
            .get(&expected_hash)
            .cloned()
        {
            return Ok(Some(code))
        }

        tracing::warn!(%address, %expected_hash, block = self.state_block_number,
            "Fetching bytecode omitted from execution witness");
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            ProviderError::Database(DatabaseError::Other("no tokio runtime found".into()))
        })?;
        let code = tokio::task::block_in_place(|| {
            handle.block_on(async {
                self.provider.get_code_at(address).number(self.state_block_number).await
            })
        })
        .map_err(|err| ProviderError::Database(DatabaseError::Other(err.to_string())))?;
        let actual_hash = keccak256(&code);
        if actual_hash != expected_hash {
            return Err(ProviderError::TrieWitnessError(format!(
                "Fetched code hash mismatch for {address}: expected {expected_hash}, got {actual_hash}"
            )))
        }
        let bytecode = Bytecode::new_raw(code);
        self.codes
            .write()
            .map_err(|_| ProviderError::TrieWitnessError("bytecode cache lock poisoned".into()))?
            .insert(expected_hash, bytecode.clone());
        Ok(Some(bytecode))
    }
}

async fn fetch_execution_witness<P, N>(
    provider: &P,
    block_number: u64,
) -> Result<ExecutionWitness, RpcDbError>
where
    P: Provider<N>,
    N: Network,
{
    let witness = provider
        .client()
        .request("debug_executionWitness", (BlockNumberOrTag::Number(block_number),))
        .await?;

    Ok(FlexibleExecutionWitness::into_execution_witness(witness))
}

#[derive(Debug, Deserialize)]
struct FlexibleExecutionWitness {
    state: Vec<alloy_primitives::Bytes>,
    codes: Vec<alloy_primitives::Bytes>,
    #[serde(default)]
    keys: Option<Vec<alloy_primitives::Bytes>>,
    headers: Vec<FlexibleExecutionWitnessHeader>,
}

impl FlexibleExecutionWitness {
    fn into_execution_witness(self) -> ExecutionWitness {
        ExecutionWitness {
            state: self.state,
            codes: self.codes,
            keys: self.keys.unwrap_or_default(),
            headers: self
                .headers
                .into_iter()
                .map(FlexibleExecutionWitnessHeader::into_rlp_bytes)
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FlexibleExecutionWitnessHeader {
    Rlp(alloy_primitives::Bytes),
    Rpc(RpcHeader<Header>),
}

impl FlexibleExecutionWitnessHeader {
    fn into_rlp_bytes(self) -> alloy_primitives::Bytes {
        match self {
            Self::Rlp(bytes) => bytes,
            Self::Rpc(header) => {
                let mut out = Vec::new();
                header.into_consensus().encode(&mut out);
                out.into()
            }
        }
    }
}

const SYSTEM_ADDRESS: Address =
    alloy_primitives::address!("0xfffffffffffffffffffffffffffffffffffffffe");

impl<P: Provider<N> + Clone, N: Network> DatabaseRef for ExecutionWitnessRpcDb<P, N> {
    type Error = ProviderError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if address == SYSTEM_ADDRESS {
            return Ok(Some(AccountInfo::default()))
        }

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
                code: self.account_code(address, account.code_hash)?,
            };

            Ok(Some(account_info))
        } else {
            Ok(None)
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.codes
            .read()
            .map_err(|_| ProviderError::TrieWitnessError("bytecode cache lock poisoned".into()))?
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
        self.codes.read().expect("bytecode cache lock poisoned").values().cloned().collect()
    }

    async fn ancestor_headers(&self) -> Result<Vec<Header>, RpcDbError> {
        Ok(self.ancestor_headers.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::{Duration, Instant},
    };

    use alloy_consensus::Header;
    use alloy_primitives::hex::FromHex;
    use alloy_rlp::Decodable;

    use super::*;

    fn code_rpc(code: &str) -> (String, thread::JoinHandle<serde_json::Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let code = code.to_string();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "no bytecode RPC request received");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(err) => panic!("{err}"),
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut bytes = Vec::new();
            let request = loop {
                let mut buffer = [0u8; 1024];
                let count = stream.read(&mut buffer).unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]);
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|value| value.trim().parse().unwrap())
                        })
                        .unwrap();
                    if bytes.len() >= end + 4 + length {
                        break serde_json::from_slice::<serde_json::Value>(
                            &bytes[end + 4..end + 4 + length],
                        )
                        .unwrap()
                    }
                }
            };
            let response =
                serde_json::json!({"jsonrpc": "2.0", "id": request["id"], "result": code})
                    .to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
            request
        });
        (url, worker)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn missing_code_uses_parent_block_and_is_cached_for_guest_input() {
        let (url, worker) = code_rpc("0x6000");
        let code = Bytecode::new_raw(alloy_primitives::bytes!("6000"));
        let hash = code.hash_slow();
        let address = Address::repeat_byte(0x11);
        let mut db = ExecutionWitnessRpcDb {
            provider: alloy_provider::ProviderBuilder::new().connect_http(url.parse().unwrap()),
            state_block_number: 26_167_641,
            state: EthereumState {
                state_trie: Default::default(),
                storage_tries: HashMap::default(),
            },
            codes: RwLock::new(HashMap::default()),
            ancestor_headers: BTreeMap::new(),
            phantom: PhantomData,
        };
        db.state
            .state_trie
            .insert_rlp(
                keccak256(address).as_slice(),
                TrieAccount {
                    nonce: 1,
                    balance: U256::from(1),
                    code_hash: hash,
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(db.basic_ref(address).unwrap().unwrap().code, Some(code.clone()));
        let request = worker.join().unwrap();
        assert_eq!(request["method"], "eth_getCode");
        assert_eq!(request["params"], serde_json::json!([address, "0x18f4959"]));
        // The RPC listener is gone: both paths must use the verified cache.
        assert_eq!(db.basic_ref(address).unwrap().unwrap().code, Some(code.clone()));
        assert_eq!(db.code_by_hash_ref(hash).unwrap(), code.clone());
        assert_eq!(db.bytecodes(), vec![code]);
        assert!(db.basic_ref(Address::repeat_byte(0x22)).unwrap().is_none());
        assert!(db.account_code(address, KECCAK_EMPTY).unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wrong_fallback_code_is_rejected_and_not_exported() {
        let (url, worker) = code_rpc("0x6001");
        let expected_hash = keccak256(alloy_primitives::bytes!("6000"));
        let address = Address::repeat_byte(0x11);
        let mut db = ExecutionWitnessRpcDb {
            provider: alloy_provider::ProviderBuilder::new().connect_http(url.parse().unwrap()),
            state_block_number: 26_167_641,
            state: EthereumState {
                state_trie: Default::default(),
                storage_tries: HashMap::default(),
            },
            codes: RwLock::new(HashMap::default()),
            ancestor_headers: BTreeMap::new(),
            phantom: PhantomData,
        };
        db.state
            .state_trie
            .insert_rlp(
                keccak256(address).as_slice(),
                TrieAccount {
                    nonce: 1,
                    balance: U256::from(1),
                    code_hash: expected_hash,
                    ..Default::default()
                },
            )
            .unwrap();

        let error = db.basic_ref(address).unwrap_err();
        worker.join().unwrap();
        assert!(error.to_string().contains("Fetched code hash mismatch"));
        assert!(db.bytecodes().is_empty());
        assert!(db.code_by_hash_ref(expected_hash).is_err());
    }

    #[test]
    fn execution_witness_accepts_rpc_header_objects_and_null_keys() {
        let json = r#"{
            "headers": [{
                "parentHash": "0xddcb9640c370c7914ccf303924421b257f05a676fc8d3c9c33ef8476194d98bd",
                "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                "miner": "0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97",
                "stateRoot": "0x043ef1fafb089e28e171f777d22845c2bdbf89e6b767857b02dcf9308de92b5c",
                "transactionsRoot": "0x751ee8f2d2893940e2b8287a72fb451ca382e5e515e8de266686e057f8cb41a7",
                "receiptsRoot": "0xc0bf6c67ff3ab702758b903204bf3f054ce68ca48dc55f8fd40e5e912b34f782",
                "logsBloom": "0xdc7d77b6e8cfcb93b6be74bdc368dba1dfecc4fdef2447324c1d84facd5cdeb2fd5e0196e6fdd5bdff93e3f9ea46adcf76bf89f8bf0e6141b5de26c0bbbf14f7cdbeb0abfedaebf95b7e7a48a5e877fd5c7ef11fb8cc9baa83445c55b8e5ffc8dee2fb19ab7e61dbcc1b9357fe0aecee5e1f7769d396fed9fef5c455bf2fff4de072397a939a5768bd69a73b3587832ab8b3c7ef653dc1de147b3973fbbb8fbfcf157d67a4d5ee5c7df5cd87dcc017a8ffd58b4d9f4c71d85dee3b2e6a1f69ffdfa75f0ef9e83edbbfe32ab7d274eedbd8cc71ff8f7e689bede5331bb0626bd6f4dde9cac72714b43eefb36df28baee2ffe36e2967fd02e2573ef7995503e7cf",
                "difficulty": "0x0",
                "number": "0x17e8a77",
                "gasLimit": "0x3938700",
                "gasUsed": "0x19aacd0",
                "timestamp": "0x6a017d13",
                "extraData": "0x546974616e2028746974616e6275696c6465722e78797a29",
                "mixHash": "0xd0d37c7118b2221b8ec1c4940be1689108309c9837a0359d41be16acdc7e546e",
                "nonce": "0x0000000000000000",
                "baseFeePerGas": "0x115394a1",
                "withdrawalsRoot": "0x978b9471e9087c6f967aaa08f757abd7280dbb7aa3310320cdd4d3fb4ecb9e5e",
                "blobGasUsed": "0x0",
                "excessBlobGas": "0xb503bd8",
                "parentBeaconBlockRoot": "0xc2b892804ed1f1f3cfeefbbc0fffd0e298bab43a7773409154a0e6ea306b794a",
                "requestsHash": "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "slotNumber": null,
                "hash": "0x190299f2eee1493723cc749ff9148663c5202f9b3479ed0da8d99ba62f882c23"
            }],
            "codes": ["0x6000"],
            "state": ["0x80"],
            "keys": null
        }"#;

        let witness = serde_json::from_str::<FlexibleExecutionWitness>(json)
            .unwrap()
            .into_execution_witness();
        let header = Header::decode(&mut witness.headers[0].as_ref()).unwrap();

        assert_eq!(header.number, 25_070_199);
        assert_eq!(witness.codes.len(), 1);
        assert_eq!(witness.state.len(), 1);
        assert!(witness.keys.is_empty());
    }

    #[test]
    fn execution_witness_preserves_rlp_header_bytes_and_keys() {
        let json = r#"{
            "headers": ["0x010203"],
            "codes": [],
            "state": [],
            "keys": ["0x04"]
        }"#;

        let witness = serde_json::from_str::<FlexibleExecutionWitness>(json)
            .unwrap()
            .into_execution_witness();

        assert_eq!(witness.headers[0].as_ref(), Vec::<u8>::from_hex("010203").unwrap());
        assert_eq!(witness.keys[0].as_ref(), Vec::<u8>::from_hex("04").unwrap());
    }
}
