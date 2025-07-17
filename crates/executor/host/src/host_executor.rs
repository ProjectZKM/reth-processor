use std::sync::Arc;

use crate::{error::SpawnedTaskError, HostError};
use alloy_consensus::{BlockHeader, Header, TxReceipt};
use alloy_evm::EthEvmFactory;
use alloy_primitives::{Bloom, Sealable};
use alloy_provider::{Network, Provider, ext::DebugApi};
use guest_executor::{
    custom::CustomEvmFactory, io::ClientExecutorInput, IntoInput, IntoPrimitives,
    ValidateBlockPostExecution,
};
use mpt::EthereumState;
use primitives::{account_proof::eip1186_proof_to_account_proof, genesis::Genesis};
use reth_chainspec::ChainSpec;
use reth_evm::{
    execute::{BasicBlockExecutor, Executor},
    ConfigureEvm,
};
use reth_trie_zkvm::ZkvmTrie;
use reth_stateless::{validation::stateless_validation_with_trie, ExecutionWitness, StatelessTrie};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::ExecutionOutcome;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::OpEvmConfig;
use reth_primitives_traits::{Block, BlockBody};
use reth_trie::KeccakKeyHasher;
use revm::database::CacheDB;
use revm_primitives::Address;
use rpc_db::RpcDb;

pub type EthHostExecutor = HostExecutor<EthEvmConfig<ChainSpec, CustomEvmFactory>, ChainSpec>;

pub type OpHostExecutor = HostExecutor<OpEvmConfig, OpChainSpec>;

/// An executor that fetches data from a [Provider] to execute blocks in the [ClientExecutor].
#[derive(Debug, Clone)]
pub struct HostExecutor<C: ConfigureEvm, CS> {
    evm_config: C,
    chain_spec: Arc<CS>,
}

impl EthHostExecutor {
    pub fn eth(chain_spec: Arc<ChainSpec>, custom_beneficiary: Option<Address>) -> Self {
        Self {
            evm_config: EthEvmConfig::new_with_evm_factory(
                chain_spec.clone(),
                CustomEvmFactory::new(custom_beneficiary),
            ),
            chain_spec,
        }
    }
}

impl OpHostExecutor {
    pub fn optimism(chain_spec: Arc<OpChainSpec>) -> Self {
        Self { evm_config: OpEvmConfig::optimism(chain_spec.clone()), chain_spec }
    }
}

impl<C: ConfigureEvm, CS> HostExecutor<C, CS> {
    /// Creates a new [HostExecutor].
    pub fn new(evm_config: C, chain_spec: Arc<CS>) -> Self {
        Self { evm_config, chain_spec }
    }

    /// Executes the block with the given block number.
    pub async fn execute<P, N>(
        &self,
        block_number: u64,
        rpc_db: &RpcDb<P, N>,
        provider: &P,
        genesis: Genesis,
        custom_beneficiary: Option<Address>,
        opcode_tracking: bool,
    ) -> Result<ClientExecutorInput<C::Primitives>, HostError>
    where
        C::Primitives: IntoPrimitives<N> + IntoInput + ValidateBlockPostExecution,
        P: Provider<N> + Clone + 'static,
        N: Network,
    {
        let chain_id: u64 = (&genesis).try_into().unwrap();
        tracing::debug!("chain id: {}", chain_id);

        // Fetch the current block and the previous block from the provider.
        tracing::info!("[{}] fetching the current block and the previous block", block_number);
        let current_block = provider
            .get_block_by_number(block_number.into())
            .full()
            .await?
            .ok_or(HostError::ExpectedBlock(block_number))
            .map(C::Primitives::into_primitive_block)?;

        let previous_block = provider
            .get_block_by_number((block_number - 1).into())
            .full()
            .await?
            .ok_or(HostError::ExpectedBlock(block_number))
            .map(C::Primitives::into_primitive_block)?;

        tracing::info!("[{}] setting up the witness for the block executor", block_number);

        let witness = provider.debug_execution_witness(
            block_number.into(),
        ).await?;

        let (parent_state, bytecodes) = ZkvmTrie::new(&witness, previous_block.header().state_root()).unwrap();

        let block = current_block
            .clone()
            .try_into_recovered()
            .map_err(|_| HostError::FailedToRecoverSenders)
            .unwrap();

        if std::env::var("DEBUG_HOST").is_ok() && std::env::var("DEBUG_HOST").unwrap() == "1" {
            let block_hash = stateless_validation_with_trie::<ZkvmTrie, ChainSpec, C>(
                &block.into_block(),
                witness,
                self.chain_spec.clone(),
                self.evm_config,
            ).unwrap();
            tracing::info!("[{}] successfully validate the block, hash: {:?}", block_number, block_hash);
        }

        // Create the client input.
        let client_input = ClientExecutorInput {
            current_block: C::Primitives::into_input_block(current_block),
            ancestor_headers: vec![], // vec![C::Primitives::into_primitive_header(previous_block)],
            parent_state,
            state_requests: Default::default(),
            bytecodes: bytecodes.into_values().collect(),
            genesis,
            custom_beneficiary,
            opcode_tracking,
        };
        tracing::info!("[{}] successfully generated client input", block_number);

        Ok(client_input)
    }
}
