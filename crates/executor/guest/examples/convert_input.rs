//! Rewrites a cached client input from the layout that shipped revm `Bytecode`
//! (with the host's jump table) to the one that ships the deployed bytes.
//!
//! Usage: convert_input <input.bin>...  (each file is rewritten in place)

use alloy_consensus::{Block, Header};
use alloy_primitives::Address;
use guest_executor::io::EthClientExecutorInput;
use mpt::EthereumState;
use primitives::genesis::Genesis;
use reth_ethereum_primitives::TransactionSigned;
use revm::state::Bytecode;
use serde::Deserialize;
use serde_with::serde_as;

#[serde_as]
#[derive(Deserialize)]
struct OldInput {
    #[serde_as(
        as = "reth_primitives_traits::serde_bincode_compat::Block<'_, TransactionSigned, Header>"
    )]
    current_block: Block<TransactionSigned>,
    #[serde_as(as = "Vec<alloy_consensus::serde_bincode_compat::Header>")]
    ancestor_headers: Vec<Header>,
    parent_state: EthereumState,
    bytecodes: Vec<Bytecode>,
    genesis: Genesis,
    custom_beneficiary: Option<Address>,
    opcode_tracking: bool,
}

fn main() {
    for path in std::env::args().skip(1) {
        let old: OldInput = bincode::deserialize(&std::fs::read(&path).unwrap()).unwrap();
        let new = EthClientExecutorInput {
            current_block: old.current_block,
            ancestor_headers: old.ancestor_headers,
            parent_state: old.parent_state,
            bytecodes: old.bytecodes.iter().map(|code| code.original_bytes()).collect(),
            genesis: old.genesis,
            custom_beneficiary: old.custom_beneficiary,
            opcode_tracking: old.opcode_tracking,
        };
        std::fs::write(&path, bincode::serialize(&new).unwrap()).unwrap();
        println!("{path}: {} bytecodes", new.bytecodes.len());
    }
}
