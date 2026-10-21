use alloy_consensus::{Block, Header};
use alloy_primitives::{Address, B256};
use guest_executor::io::{EthClientExecutorInput, RawCode};
use mpt::WitnessState;
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
    parent_state: WitnessState,
    bytecodes: Vec<Bytecode>,
    code_hashes: Vec<B256>,
    genesis: Genesis,
    custom_beneficiary: Option<Address>,
    opcode_tracking: bool,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let old: OldInput = bincode::deserialize(&std::fs::read(&args[1]).unwrap()).unwrap();
    let old_codes = old.bytecodes.clone();
    let new = EthClientExecutorInput {
        current_block: old.current_block,
        ancestor_headers: old.ancestor_headers,
        parent_state: old.parent_state,
        bytecodes: old.bytecodes.iter().map(|b| RawCode::new(b.original_byte_slice())).collect(),
        code_hashes: old.code_hashes,
        genesis: old.genesis,
        custom_beneficiary: old.custom_beneficiary,
        opcode_tracking: old.opcode_tracking,
    };
    for (old, new) in old_codes.iter().zip(&new.bytecodes) {
        let analyzed = new.analyze();
        assert_eq!(old.original_byte_slice(), analyzed.original_byte_slice());
        assert_eq!(
            old.legacy_jump_table().map(|j| j.as_slice().to_vec()),
            analyzed.legacy_jump_table().map(|j| j.as_slice().to_vec()),
            "jump table"
        );
    }
    let bytes = bincode::serialize(&new).unwrap();
    std::fs::write(&args[2], &bytes).unwrap();
    println!("wrote {} bytes", bytes.len());
}
