#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// Client program input data types.
pub mod io;
#[macro_use]
mod utils;
pub mod custom;
pub mod error;
pub mod executor;
pub mod hashed_keys;
pub mod precompiles;
pub mod tracking;

mod into_primitives;
pub use into_primitives::{BlockValidator, FromInput, IntoInput, IntoPrimitives};

use alloy_primitives::B256;
use executor::{EthClientExecutor, DESERIALZE_INPUTS};
use io::EthClientExecutorInput;
use std::sync::Arc;

/// Verifies an Ethereum mainnet block and returns its hash, its state root and
/// its parent's.
///
/// The proof commits only the block hash, so the rules the block runs under
/// must not come from the prover: the input's chain must be mainnet, with no
/// beneficiary override (a Clique-only setting that redirects block rewards).
pub fn verify_block(input: &[u8]) -> (B256, B256, B256) {
    println!("cycle-tracker-report-start: {DESERIALZE_INPUTS}");
    let input = bincode::deserialize::<EthClientExecutorInput>(input).unwrap();
    println!("cycle-tracker-report-end: {DESERIALZE_INPUTS}");
    assert!(
        matches!(input.genesis, primitives::genesis::Genesis::Mainnet),
        "the guest verifies Ethereum mainnet blocks only"
    );
    assert!(input.custom_beneficiary.is_none(), "mainnet blocks pay the header's beneficiary");

    // Execute the block.
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );
    let (header, prev_state_root) = executor.execute(input).expect("failed to execute client");
    let block_hash = header.hash_slow();
    (block_hash, header.state_root, prev_state_root)
}
