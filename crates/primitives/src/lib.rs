#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod account_proof;
pub mod chain_spec;
pub mod genesis;

use alloy_primitives::Address;

#[inline]
pub fn is_goat_testnet(chain_id: u64) -> bool {
    chain_id == 48816
}

#[inline]
pub fn is_precompile(address: Address) -> bool {
    let bytes = address.as_slice();
    // Check if the first 19 bytes are zero.
    if !bytes[..19].iter().all(|&b| b == 0) {
        return false;
    }
    // Check if the last byte is non-zero (so it is not the zero address).
    let last = bytes[19];

    last > 0
}
