use std::{fs, path::PathBuf};

use alloy_chains::Chain;
use alloy_primitives::Address;
use alloy_provider::{network::AnyNetwork, Provider, RootProvider};
use clap::Parser;
use host_executor::Config;
use primitives::genesis::Genesis;
use url::Url;
use zkm_sdk::ZKMProofKind;

/// The arguments for the host executable.
#[derive(Debug, Clone, Parser)]
pub struct HostArgs {
    /// The block number of the block to execute.
    #[clap(long)]
    pub block_number: u64,

    #[clap(flatten)]
    pub provider: ProviderArgs,

    /// The path to the genesis json file to use for the execution.
    #[clap(long)]
    pub genesis_path: Option<PathBuf>,

    /// The custom beneficiary address, used with Clique consensus.
    #[clap(long)]
    pub custom_beneficiary: Option<Address>,

    /// Whether to generate a proof or just execute the block.
    #[clap(long)]
    pub prove: bool,

    /// Optional path to the directory containing cached client input. A new cache file will be
    /// created from RPC data if it doesn't already exist.
    #[clap(long)]
    pub cache_dir: Option<PathBuf>,

    /// The path to the CSV file containing the execution data.
    #[clap(long, default_value = "report.csv")]
    pub report_path: PathBuf,

    #[clap(long)]
    /// Whether to track the cycle count of precompiles.
    pub precompile_tracking: bool,
    #[clap(long)]
    /// Whether to track the cycle count of opcodes.
    pub opcode_tracking: bool,
}

impl HostArgs {
    pub async fn as_config(&self) -> eyre::Result<Config> {
        // We don't need RPC when using cache with known chain ID, so we leave it as `Option<Url>`
        // here and decide on whether to panic later.
        //
        // On the other hand chain ID is always needed.
        let (rpc_url, chain_id) = match (self.provider.rpc_url.clone(), self.provider.chain_id) {
            (Some(rpc_url), Some(chain_id)) => (Some(rpc_url), chain_id),
            (None, Some(chain_id)) => {
                match std::env::var(format!("RPC_{}", chain_id)) {
                    Ok(rpc_env_var) => {
                        // We don't always need it but if the value exists it has to be valid.
                        (Some(Url::parse(rpc_env_var.as_str())?), chain_id)
                    }
                    Err(_) => {
                        // Not having RPC is okay because we know chain ID.
                        (None, chain_id)
                    }
                }
            }
            (Some(rpc_url), None) => {
                // We can find out about chain ID from RPC.
                let provider = RootProvider::<AnyNetwork>::new_http(rpc_url.clone());

                (Some(rpc_url), provider.get_chain_id().await?)
            }
            (None, None) => {
                eyre::bail!("either --rpc-url or --chain-id must be used")
            }
        };
        let debug_rpc_url = self.provider.debug_rpc_url.clone().or_else(|| {
            std::env::var(format!("DEBUG_RPC_{}", chain_id))
                .ok()
                .and_then(|url| Url::parse(&url).ok())
        });
        let debug_rpc_url = debug_rpc_url.or_else(|| rpc_url.clone());

        let witness_rpc_url = self.provider.witness_rpc_url.clone().or_else(|| {
            std::env::var(format!("WITNESS_RPC_{}", chain_id))
                .ok()
                .and_then(|url| Url::parse(&url).ok())
        });
        let witness_rpc_url = witness_rpc_url.or_else(|| rpc_url.clone());

        let genesis = if let Some(genesis_path) = &self.genesis_path {
            let genesis_json = fs::read_to_string(genesis_path)
                .map_err(|err| eyre::eyre!("Failed to read genesis file: {err}"))?;

            Genesis::Custom(genesis_json)
        } else {
            chain_id.try_into()?
        };

        let chain = Chain::from_id(chain_id);

        let config = Config {
            chain,
            genesis,
            rpc_url,
            debug_rpc_url,
            witness_rpc_url,
            cache_dir: self.cache_dir.clone(),
            custom_beneficiary: self.custom_beneficiary,
            prove_mode: self.prove.then_some(ZKMProofKind::Compressed),
            // prove_mode: self.prove.then_some(ZKMProofKind::Core),
            opcode_tracking: self.opcode_tracking,
        };

        Ok(config)
    }
}

/// The arguments for configuring the chain data provider.
#[derive(Debug, Clone, Parser)]
pub struct ProviderArgs {
    /// The rpc url used to fetch data about the block. If not provided, will use the
    /// RPC_{chain_id} env var.
    #[clap(long)]
    pub rpc_url: Option<Url>,
    /// The debug rpc url used to fetch data about the block trace. If not provided, will use the
    /// DEBUG_RPC_{chain_id} env var. If DEBUG_RPC_{chain_id} is not set, will use the rpc_url.
    #[clap(long)]
    pub debug_rpc_url: Option<Url>,
    /// The debug rpc url used to the block exection witness. If not provided, will use the
    /// WITNESS_RPC_{chain_id} env var. If WITNESS_RPC_{chain_id} is not set, will use the rpc_url.
    #[clap(long)]
    pub witness_rpc_url: Option<Url>,
    /// The chain ID. If not provided, requires the rpc_url argument to be provided.
    #[clap(long)]
    pub chain_id: Option<u64>,
}
