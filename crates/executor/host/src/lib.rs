#![cfg_attr(not(test), allow(unused_crate_dependencies))]

use alloy_chains::Chain;
use alloy_evm::EthEvmFactory;
pub use error::Error as HostError;
use guest_executor::custom::CustomEvmFactory;
use primitives::genesis::Genesis;
use reth_chainspec::ChainSpec;
use reth_evm_ethereum::EthEvmConfig;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::OpEvmConfig;
use revm_primitives::Address;
use std::{path::PathBuf, sync::Arc};
use url::Url;
use zkm_sdk::ZKMProofKind;

#[cfg(feature = "alerting")]
pub mod alerting;

pub mod bins;

mod error;

mod executor_components;
pub use executor_components::{EthExecutorComponents, ExecutorComponents, OpExecutorComponents};

mod full_executor;
pub use full_executor::{build_executor, BlockExecutor, EitherExecutor, FullExecutor};

mod hooks;
pub use hooks::ExecutionHooks;

mod host_executor;
pub use host_executor::{EthHostExecutor, HostExecutor, OpHostExecutor};

mod utils;

pub fn create_eth_block_execution_strategy_factory(
    genesis: &Genesis,
    custom_beneficiary: Option<Address>,
) -> EthEvmConfig<CustomEvmFactory<EthEvmFactory>> {
    let chain_spec: Arc<ChainSpec> = Arc::new(genesis.try_into().unwrap());

    EthEvmConfig::new_with_evm_factory(
        chain_spec,
        CustomEvmFactory::<EthEvmFactory>::new(custom_beneficiary),
    )
}

pub fn create_op_block_execution_strategy_factory(genesis: &Genesis) -> OpEvmConfig {
    let chain_spec: Arc<OpChainSpec> = Arc::new(genesis.try_into().unwrap());

    OpEvmConfig::optimism(chain_spec)
}
#[derive(Debug)]
pub struct Config {
    pub chain: Chain,
    pub genesis: Genesis,
    pub rpc_url: Option<Url>,
    pub debug_rpc_url: Option<Url>,
    pub cache_dir: Option<PathBuf>,
    pub custom_beneficiary: Option<Address>,
    pub prove_mode: Option<ZKMProofKind>,
    pub opcode_tracking: bool,
}

impl Config {
    pub fn mainnet() -> Self {
        Self {
            chain: Chain::mainnet(),
            genesis: Genesis::Mainnet,
            rpc_url: None,
            debug_rpc_url: None,
            cache_dir: None,
            custom_beneficiary: None,
            prove_mode: None,
            opcode_tracking: false,
        }
    }
}
