use alloy_chains::Chain;
use clap::Parser;
use host_executor::Config;
use primitives::genesis::Genesis;
use url::Url;
use zkm_sdk::ZKMProofKind;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    /// The HTTP rpc url used to fetch data about the block.
    #[clap(long, env)]
    pub http_rpc_url: Url,

    /// The WS rpc url used to fetch data about the block.
    #[clap(long, env)]
    pub ws_rpc_url: Option<Url>,

    /// The debug HTTP rpc url used to fetch data about the block trace.
    #[clap(long, env)]
    pub debug_http_rpc_url: Url,

    /// Whether to generate a proof or just execute the block.
    #[clap(long)]
    pub execute_only: bool,

    /// The interval at which to execute blocks.
    #[clap(long, default_value_t = 100)]
    pub block_interval: u64,

    /// Which residue class of `block_interval` this instance proves: blocks
    /// with `number % block_interval == block_residue`.  Two instances with
    /// `--block-interval 2` and residues 0 and 1 split the chain between two
    /// provers and prove two blocks at a time.
    #[clap(long, default_value_t = 0)]
    pub block_residue: u64,

    /// How many prepared blocks (fetched + natively executed) may wait for the
    /// prover.  The fetch of block N+1 always overlaps the proof of block N;
    /// this bounds how far ahead the fetcher runs.
    #[clap(long, default_value_t = 1)]
    pub prefetch_depth: usize,

    /// Skip a block when it is more than this many blocks behind the newest
    /// header seen (0 = never skip: prove every block the stream delivers).
    #[clap(long, default_value_t = 0)]
    pub max_lag: u64,

    /// In local mode, select the latest eligible head before each preparation.
    /// Prepare ahead of proving; retain only the newest completed witness.
    #[clap(long)]
    pub latest_block: bool,

    /// ETH proofs endpoint.
    #[clap(long, env)]
    pub eth_proofs_endpoint: String,

    /// ETH proofs API token.
    #[clap(long, env)]
    pub eth_proofs_api_token: String,

    /// Optional ETH proofs cluster ID.
    #[clap(long, default_value_t = 1)]
    pub eth_proofs_cluster_id: u64,

    /// PagerDuty integration key.
    #[clap(long, env)]
    pub pager_duty_integration_key: Option<String>,

    /// Direct local GPU server, set by Fleet for an integrated app worker.
    #[clap(long, env = "FLEET_GPU_ENDPOINT")]
    pub local_gpu_endpoint: Option<Url>,

    /// Persistent local worker state. Required with --local-gpu-endpoint.
    #[clap(long, env = "FLEET_APP_STORAGE_ROOT", requires = "local_gpu_endpoint")]
    pub state_dir: Option<std::path::PathBuf>,

    /// Use an existing production guest instead of the embedded ELF.
    #[clap(long, env = "ETH_PROOFS_ELF_FILE")]
    pub elf_file: Option<std::path::PathBuf>,

    /// Reject a guest whose digest differs from this app's configured program.
    #[clap(long, env = "FLEET_APP_ELF_ID")]
    pub expected_elf_id: Option<String>,

    /// First block for a new durable stream; restarts resume persisted progress.
    #[clap(long)]
    pub start_block: Option<u64>,

    /// Witness preparation concurrency (1 or 2 in latest mode; GPU proving remains serial).
    #[clap(long, default_value_t = 1)]
    pub prepare_concurrency: usize,

    /// Pause proving when this many completed reports await acknowledgment.
    #[clap(long, default_value_t = 128)]
    pub max_pending_reports: usize,

    /// Moongate server endpoint.
    #[clap(long, env)]
    pub moongate_endpoint: Option<String>,
}

impl Args {
    pub async fn as_config(&self) -> eyre::Result<Config> {
        let config = Config {
            chain: Chain::mainnet(),
            genesis: Genesis::Mainnet,
            rpc_url: Some(self.http_rpc_url.clone()),
            debug_rpc_url: Some(self.debug_http_rpc_url.clone()),
            cache_dir: None,
            custom_beneficiary: None,
            prove_mode: (!self.execute_only).then_some(ZKMProofKind::Compressed),
            opcode_tracking: false,
        };

        Ok(config)
    }
}
