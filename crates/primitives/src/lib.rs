#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod account_proof;
pub mod chain_spec;
pub mod genesis;

#[inline]
pub fn is_goat_testnet(chain_id: u64) -> bool {
    chain_id == 48816
}
