use std::iter::once;

use alloy_consensus::{Block, BlockHeader, Header};
use alloy_primitives::map::HashMap;
use itertools::Itertools;
use mpt::{ArenaState, WitnessState};
use primitives::genesis::Genesis;
use reth_errors::ProviderError;
use reth_ethereum_primitives::EthPrimitives;
use reth_primitives_traits::{NodePrimitives, SealedHeader};
use revm::{
    bytecode::{eip7702::EIP7702_MAGIC_BYTES, JumpTable, LegacyAnalyzedBytecode},
    state::{AccountInfo, Bytecode},
    DatabaseRef,
};
use revm_primitives::{keccak256, Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::error::ClientError;

pub type EthClientExecutorInput = ClientExecutorInput<EthPrimitives>;

#[cfg(feature = "optimism")]
pub type OpClientExecutorInput = ClientExecutorInput<reth_optimism_primitives::OpPrimitives>;

/// The input for the client to execute a block and fully verify the STF (state transition
/// function).
///
/// Instead of passing in the entire state, we only pass in the state roots along with merkle proofs
/// for the storage slots that were modified and accessed.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientExecutorInput<P: NodePrimitives> {
    /// The current block (which will be executed inside the client).
    #[serde_as(
        as = "reth_primitives_traits::serde_bincode_compat::Block<'_, P::SignedTx, Header>"
    )]
    pub current_block: Block<P::SignedTx>,
    /// The previous block headers starting from the most recent. There must be at least one header
    /// to provide the parent state root.
    #[serde_as(as = "Vec<alloy_consensus::serde_bincode_compat::Header>")]
    pub ancestor_headers: Vec<Header>,
    /// Network state as of the parent block, in witness form (root hashes and
    /// preorder streams of raw RLP nodes); the guest materialises it into an
    /// [`ArenaState`], checking every node against the digest that references it.
    pub parent_state: WitnessState,
    /// Account bytecodes, as deployed: the guest derives the jump table
    /// itself, since one taken from the host would decide which jumps are
    /// valid without being bound by the code hash.
    pub bytecodes: Vec<RawCode>,
    /// The code hash the host claims for each entry of `bytecodes`; the guest
    /// checks a claim the first time that code executes, so code that is only
    /// shipped (touched accounts that never run) is never hashed.
    #[serde(default)]
    pub code_hashes: Vec<B256>,
    /// The genesis block, as a json string.
    pub genesis: Genesis,
    /// The genesis block, as a json string.
    pub custom_beneficiary: Option<Address>,
    /// Whether to track the cycle count of opcodes.
    pub opcode_tracking: bool,
}

impl<P: NodePrimitives> ClientExecutorInput<P> {
    /// Gets the immediate parent block's header.
    #[inline(always)]
    pub fn parent_header(&self) -> &Header {
        self.ancestor_headers.last().unwrap()
    }

    /// Creates a [`TrieDB`] over the materialised `state`.
    pub fn witness_db<'a>(
        &'a self,
        state: &'a ArenaState,
        sealed_headers: &[SealedHeader],
    ) -> Result<TrieDB<'a>, ClientError> {
        <Self as WitnessInput>::witness_db(self, state, sealed_headers)
    }
}

impl<P: NodePrimitives> WitnessInput for ClientExecutorInput<P> {
    #[inline(always)]
    fn state(&self) -> &WitnessState {
        &self.parent_state
    }

    #[inline(always)]
    fn state_anchor(&self) -> B256 {
        self.parent_header().state_root()
    }

    #[inline(always)]
    fn bytecodes(&self) -> impl Iterator<Item = &RawCode> {
        self.bytecodes.iter()
    }

    #[inline(always)]
    fn code_hashes(&self) -> &[B256] {
        &self.code_hashes
    }

    #[inline(always)]
    fn sealed_headers(&self) -> impl Iterator<Item = SealedHeader> {
        self.ancestor_headers
            .iter()
            .map(|h| SealedHeader::seal_slow(h.clone()))
            .chain(once(SealedHeader::seal_slow(self.current_block.header.clone())))
    }
}

/// A contract's code as deployed followed by [`RawCode::PADDING`] zero
/// bytes, read from the input without a copy.  The zeros are the `STOP`s the
/// interpreter runs into past the end of the code, at most a 32-byte push
/// operand and one `STOP`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawCode(#[serde(deserialize_with = "mpt::input_bytes")] pub Bytes);

impl RawCode {
    pub const PADDING: usize = 33;

    /// `code` with its padding.
    pub fn new(code: &[u8]) -> Self {
        let mut padded = Vec::with_capacity(code.len() + Self::PADDING);
        padded.extend_from_slice(code);
        padded.resize(code.len() + Self::PADDING, 0);
        Self(padded.into())
    }

    /// The code as deployed.
    pub fn code(&self) -> &[u8] {
        &self.0[..self.0.len() - Self::PADDING]
    }

    /// The analyzed bytecode: its jump table derived here, the padding
    /// checked to be zeros.
    ///
    /// # Panics
    /// Panics if the padding is missing or not zero.
    pub fn analyze(&self) -> Bytecode {
        let len = self.0.len().checked_sub(Self::PADDING).expect("code padding");
        assert!(self.0[len..].iter().all(|&b| b == 0), "code padding is not zero");
        let code = &self.0[..len];
        if code.starts_with(&EIP7702_MAGIC_BYTES) {
            return Bytecode::new_raw(self.0.slice(..len));
        }
        let jump_table = JumpTable::from_bytes(jump_table(&self.0, len).into(), len);
        Bytecode::LegacyAnalyzed(LegacyAnalyzedBytecode::new(self.0.clone(), len, jump_table))
    }
}

/// Bytes an opcode spans, its own byte included: `n + 1` for `PUSHn`, else 1.
const OPCODE_SPAN: [u8; 256] = {
    let mut span = [1u8; 256];
    let mut n = 1;
    while n <= 32 {
        span[0x5f + n] = n as u8 + 1;
        n += 1;
    }
    span
};

/// The `JUMPDEST` bitmap of the first `len` bytes of `padded`, bit `i & 7` of
/// byte `i >> 3` set when byte `i` starts an instruction and is `0x5b`.
///
/// The walk reads only bytes below `len`; a push operand may carry the
/// cursor up to 32 bytes past it, which ends the walk.  The raw pointers are
/// sound because the cursor is compared against the end before every read
/// and `i >> 3 < ⌈len/8⌉` for every `i < len`.
fn jump_table(padded: &[u8], len: usize) -> Vec<u8> {
    assert!(len <= padded.len());
    let mut table = vec![0u8; len.div_ceil(8)];
    let base = padded.as_ptr();
    let end = base.wrapping_add(len);
    let mut p = base;
    while p < end {
        let op = unsafe { *p };
        if op == revm::bytecode::opcode::JUMPDEST {
            let i = p as usize - base as usize;
            unsafe { *table.get_unchecked_mut(i >> 3) |= 1 << (i & 7) };
        }
        p = p.wrapping_add(OPCODE_SPAN[op as usize] as usize);
    }
    table
}

#[derive(Debug)]
pub struct TrieDB<'a> {
    inner: &'a ArenaState,
    block_hashes: HashMap<u64, B256>,
    /// Keyed by the host's CLAIMED hash; a claim is trusted only after
    /// `verified_code` holds its analysis.
    bytecode_by_hash: HashMap<B256, &'a RawCode>,
    verified_code: core::cell::RefCell<HashMap<B256, Bytecode>>,
}

impl<'a> TrieDB<'a> {
    pub fn new(
        inner: &'a ArenaState,
        block_hashes: HashMap<u64, B256>,
        bytecode_by_hash: HashMap<B256, &'a RawCode>,
    ) -> Self {
        Self { inner, block_hashes, bytecode_by_hash, verified_code: Default::default() }
    }
}

/// The system address used for system calls.
const SYSTEM_ADDRESS: Address =
    alloy_primitives::address!("0xfffffffffffffffffffffffffffffffffffffffe");

impl DatabaseRef for TrieDB<'_> {
    /// The database error type.
    type Error = ProviderError;

    /// Get basic account information.
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if address == SYSTEM_ADDRESS {
            return Ok(Some(AccountInfo::default()))
        }

        let hashed_address = keccak256(address);
        let hashed_address = hashed_address.as_slice();

        let account_in_trie = self.inner.account(hashed_address).unwrap();

        let account = account_in_trie.map(|account_in_trie| AccountInfo {
            balance: account_in_trie.balance,
            nonce: account_in_trie.nonce,
            code_hash: account_in_trie.code_hash,
            code: None,
        });

        Ok(account)
    }

    /// Get account code by its hash.
    ///
    /// The claimed hash is checked, and the jump table derived, the first time
    /// the code is used; a wrong claim aborts the execution.
    fn code_by_hash_ref(&self, hash: B256) -> Result<Bytecode, Self::Error> {
        if let Some(code) = self.verified_code.borrow().get(&hash) {
            return Ok(code.clone());
        }
        let raw = *self.bytecode_by_hash.get(&hash).expect("bytecode for hash must be provided");
        assert_eq!(keccak256(raw.code()), hash, "bytecode does not match its claimed hash");
        let code = raw.analyze();
        self.verified_code.borrow_mut().insert(hash, code.clone());
        Ok(code)
    }

    /// Get storage value of address at index.
    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let hashed_address = keccak256(address);

        Ok(self
            .inner
            .storage(&hashed_address, keccak256(index.to_be_bytes::<32>()).as_slice())
            .expect("Can get from MPT")
            .unwrap_or_default())
    }

    /// Get block hash by block number.
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        Ok(*self
            .block_hashes
            .get(&number)
            .expect("A block hash must be provided for each block number"))
    }
}

/// A trait for constructing [`WitnessDb`].
pub trait WitnessInput {
    /// Gets the witness state from which account info and storage slots are loaded.
    fn state(&self) -> &WitnessState;

    /// Gets the state trie root hash that the state referenced by
    /// [state()](trait.WitnessInput#tymethod.state) must conform to.
    fn state_anchor(&self) -> B256;

    /// Gets an iterator over account bytecodes, as deployed.
    fn bytecodes(&self) -> impl Iterator<Item = &RawCode>;

    /// The claimed code hash of each bytecode, in the same order.
    fn code_hashes(&self) -> &[B256];

    /// Gets an iterator over references to a consecutive, reverse-chronological block headers
    /// starting from the current block header.
    fn sealed_headers(&self) -> impl Iterator<Item = SealedHeader>;

    /// Creates a [`WitnessDb`] from a [`WitnessInput`] implementation. To do so, it verifies the
    /// state root, ancestor headers and account bytecodes, and constructs the account and
    /// storage values by reading against state tries.
    ///
    /// NOTE: For some unknown reasons, calling this trait method directly from outside of the type
    /// implementing this trait causes a zkVM run to cost over 5M cycles more. To avoid this, define
    /// a method inside the type that calls this trait method instead.
    #[inline(always)]
    fn witness_db<'a>(
        &'a self,
        state: &'a ArenaState,
        sealed_headers: &[SealedHeader],
    ) -> Result<TrieDB<'a>, ClientError> {
        // `state` was built from `self.state()`: every node keccak-checked
        // against its parent's digest, the state trie against
        // `state_root`, every storage trie against its account's storage
        // root.  What remains is binding that root to the parent header.
        if self.state_anchor() != self.state().state_root {
            return Err(ClientError::MismatchedStateRoot);
        }

        // Bytecodes are indexed by the host's claimed hash and verified on
        // first use (see `TrieDB::code_by_hash_ref`); hashing every shipped
        // contract up front was ~8 M cycles on a reth block, much of it for
        // code that never runs.
        let claimed = self.code_hashes();
        if claimed.len() != self.bytecodes().count() {
            return Err(ClientError::InvalidWitness("code_hashes/bytecodes length mismatch".into()));
        }
        let bytecodes_by_hash =
            claimed.iter().copied().zip(self.bytecodes()).collect::<HashMap<_, _>>();

        // Verify and build block hashes
        let mut block_hashes: HashMap<u64, B256> = HashMap::with_hasher(Default::default());
        for (parent_header, child_header) in sealed_headers.iter().tuple_windows() {
            if parent_header.number() != child_header.number() - 1 {
                return Err(ClientError::InvalidHeaderBlockNumber(
                    parent_header.number() + 1,
                    child_header.number(),
                ));
            }

            let parent_header_hash = parent_header.hash_slow();
            if parent_header_hash != child_header.parent_hash() {
                return Err(ClientError::InvalidHeaderParentHash(
                    parent_header_hash,
                    child_header.parent_hash(),
                ));
            }

            block_hashes.insert(parent_header.number(), child_header.parent_hash());
        }

        Ok(TrieDB::new(state, block_hashes, bytecodes_by_hash))
    }
}
