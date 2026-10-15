//! Memoised keccak of trie keys.
//!
//! A block hashes the same account addresses and storage slots many times:
//! [`TrieDB`](crate::io::TrieDB) hashes both on every read, and the post-state
//! root pass hashes every changed account and slot again.  In the zkVM each of
//! those is a KeccakSponge precompile call, and that chip is about a third of a
//! block's proving area, so a repeat costs far more than the map probe that
//! avoids it (block 25955640: 17,311 of its 22,298 address and slot hashes were
//! repeats).
//!
//! The memo only ever holds digests this execution computed itself, so a hit
//! returns exactly what a fresh keccak would.  Off the zkVM the functions hash
//! directly: the host runs one block after another in one process, where a
//! per-thread memo would only grow.

use alloy_primitives::{keccak256, Address, B256};
use reth_trie::KeyHasher;

#[cfg(target_os = "zkvm")]
mod memo {
    use std::cell::RefCell;

    use alloy_primitives::{keccak256, map::HashMap, Address, B256};

    thread_local! {
        static ADDRESSES: RefCell<HashMap<Address, B256>> = RefCell::new(HashMap::default());
        static SLOTS: RefCell<HashMap<B256, B256>> = RefCell::new(HashMap::default());
    }

    pub(super) fn address(address: Address) -> B256 {
        ADDRESSES.with(|m| *m.borrow_mut().entry(address).or_insert_with(|| keccak256(address)))
    }

    pub(super) fn slot(slot: B256) -> B256 {
        SLOTS.with(|m| *m.borrow_mut().entry(slot).or_insert_with(|| keccak256(slot)))
    }
}

/// `keccak256(address)`, the account's key in the state trie.
#[inline]
pub fn hashed_address(address: Address) -> B256 {
    #[cfg(target_os = "zkvm")]
    return memo::address(address);
    #[cfg(not(target_os = "zkvm"))]
    keccak256(address)
}

/// `keccak256(slot)`, the slot's key in its storage trie.
#[inline]
pub fn hashed_slot(slot: B256) -> B256 {
    #[cfg(target_os = "zkvm")]
    return memo::slot(slot);
    #[cfg(not(target_os = "zkvm"))]
    keccak256(slot)
}

/// [`KeccakKeyHasher`](reth_trie::KeccakKeyHasher) through the memo: the
/// post-state pass hands it 20-byte addresses and 32-byte slots.
#[derive(Clone, Debug, Default)]
pub struct MemoKeyHasher;

impl KeyHasher for MemoKeyHasher {
    #[inline]
    fn hash_key<T: AsRef<[u8]>>(bytes: T) -> B256 {
        let bytes = bytes.as_ref();
        match bytes.len() {
            20 => hashed_address(Address::from_slice(bytes)),
            32 => hashed_slot(B256::from_slice(bytes)),
            _ => keccak256(bytes),
        }
    }
}
