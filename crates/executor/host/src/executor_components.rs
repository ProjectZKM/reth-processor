use std::marker::PhantomData;

use alloy_evm::EthEvmFactory;
use alloy_network::Ethereum;
use alloy_provider::Network;
use guest_executor::{
    IntoInput, IntoPrimitives, ValidateBlockPostExecution,
    custom::CustomEvmFactory,
};
use op_alloy_network::Optimism;
use reth_ethereum_primitives::EthPrimitives;
use reth_evm::ConfigureEvm;
use reth_optimism_chainspec::OpChainSpec;
use reth_evm_ethereum::EthEvmConfig;
use reth_optimism_evm::OpEvmConfig;
use reth_optimism_primitives::OpPrimitives;
use reth_primitives_traits::NodePrimitives;
use reth_chainspec::ChainSpec;
use primitives::genesis::Genesis;
use serde::de::DeserializeOwned;
use zkm_prover::components::DefaultProverComponents;
use zkm_sdk::{Prover, ProverClient};

use crate::ExecutionHooks;

pub trait ExecutorComponents {
    type Prover: Prover<DefaultProverComponents> + 'static;

    type Network: Network;

    type Primitives: NodePrimitives
        + DeserializeOwned
        + IntoPrimitives<Self::Network>
        + IntoInput
        + ValidateBlockPostExecution;

    type EvmConfig: ConfigureEvm<Primitives = Self::Primitives>;

    type ChainSpec;

    type Hooks: ExecutionHooks;

    fn try_into_chain_spec(genesis: &Genesis) -> eyre::Result<Self::ChainSpec>;
}

#[derive(Debug, Default)]
pub struct EthExecutorComponents<H, P = ProverClient> {
    phantom: PhantomData<(H, P)>,
}

impl<H, P> ExecutorComponents for EthExecutorComponents<H, P>
where
    H: ExecutionHooks,
    P: Prover<DefaultProverComponents> + 'static,
{
    type Prover = P;

    type Network = Ethereum;

    type Primitives = EthPrimitives;

    type EvmConfig = EthEvmConfig<ChainSpec, CustomEvmFactory>;

    type ChainSpec = ChainSpec;

    type Hooks = H;

    fn try_into_chain_spec(genesis: &Genesis) -> eyre::Result<ChainSpec> {
        let spec = genesis.try_into()?;
        Ok(spec)
    }
}

#[derive(Debug, Default)]
pub struct OpExecutorComponents<H, P = ProverClient> {
    phantom: PhantomData<(H, P)>,
}

impl<H, P> ExecutorComponents for OpExecutorComponents<H, P>
where
    H: ExecutionHooks,
    P: Prover<DefaultProverComponents> + 'static,
{
    type Prover = P;

    type Network = Optimism;

    type Primitives = OpPrimitives;

    type EvmConfig = OpEvmConfig;

    type ChainSpec = OpChainSpec;

    type Hooks = H;

    fn try_into_chain_spec(genesis: &Genesis) -> eyre::Result<OpChainSpec> {
        let spec = genesis.try_into()?;
        Ok(spec)
    }
}
