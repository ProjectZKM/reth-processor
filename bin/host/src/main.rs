use std::sync::Arc;

use clap::Parser;
use host_executor::{
    bins::persist_report_hook::PersistExecutionReport, build_executor,
    create_eth_block_execution_strategy_factory, BlockExecutor, EthExecutorComponents,
};
use provider::create_provider;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};
#[cfg(feature = "network_prover")]
use zkm_sdk::NetworkProver;
use zkm_sdk::{include_elf, ProverClient};

mod cli;
use cli::HostArgs;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // Initialize the logger.
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env()
                .add_directive("zkm_core_machine=warn".parse().unwrap())
                .add_directive("zkm_core_executor::executor=warn".parse().unwrap())
                .add_directive("zkm_prover=warn".parse().unwrap())
                .add_directive("zkm_sdk=info".parse().unwrap()),
        )
        .init();

    // Parse the command line arguments.
    let args = HostArgs::parse();
    let block_number = args.block_number;
    let report_path = args.report_path.clone();
    let config = args.as_config().await?;
    let persist_execution_report = PersistExecutionReport::new(
        config.chain.id(),
        report_path,
        args.precompile_tracking,
        args.opcode_tracking,
    );

    #[cfg(feature = "network_prover")]
    let prover_client = {
        let np = NetworkProver::from_env().map_err(|_| {
            eyre::eyre!("Failed to create NetworkProver from environment variables")
        })?;
        Arc::new(np)
    };
    #[cfg(not(feature = "network_prover"))]
    let prover_client = {
        tracing::info!("Use local ProverClient");
        Arc::new(ProverClient::new())
    };

    let elf = include_elf!("reth").to_vec();
    let block_execution_strategy_factory =
        create_eth_block_execution_strategy_factory(&config.genesis, config.custom_beneficiary);
    let provider = config.rpc_url.as_ref().map(|url| create_provider(url.clone()));
    let debug_provider = config.debug_rpc_url.as_ref().map(|url| create_provider(url.clone()));

    let executor = build_executor::<EthExecutorComponents<_, _>, _>(
        elf,
        provider,
        debug_provider,
        block_execution_strategy_factory,
        prover_client,
        persist_execution_report,
        config,
    )
    .await?;

    executor.execute(block_number).await?;

    Ok(())
}
