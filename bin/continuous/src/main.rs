use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use alloy_provider::{network::Ethereum, Provider};
use clap::Parser;
use cli::Args;
use host_executor::{
    alerting::AlertingClient, create_eth_block_execution_strategy_factory, BlockExecutor,
    EthExecutorComponents, ExecutorComponents, FullExecutor,
};
use provider::create_provider;
use tokio::{sync::Semaphore, task};
use tracing::{error, info, instrument, warn};
use tracing_subscriber::util::SubscriberInitExt;
use zkm_sdk::{include_elf, ProverClient};

mod cli;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    let args = Args::parse();

    // Initialize the logger.
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt()
        .with_env_filter(
            "continuous=info,host-executor=info,zkm_core_machine=warn,zkm_core_executor=error,zkm_prover=warn,zkm-sdk=info",
        )
        .with_writer(non_blocking)
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .finish()
        .init();

    let config = args.as_config().await?;
    info!("args: {:?}", args);

    let elf = include_elf!("reth").to_vec();
    let block_execution_strategy_factory =
        create_eth_block_execution_strategy_factory(&config.genesis, None);

    tracing::info!("first block number: {}", args.block_number);

    let http_provider = create_provider(config.rpc_url.clone().unwrap());
    let alerting_client =
        args.pager_duty_integration_key.map(|key| Arc::new(AlertingClient::new(key)));

    let prover_client = Arc::new(ProverClient::new());

    let executor = Arc::new(
        FullExecutor::<EthExecutorComponents<_, _>, _>::try_new(
            http_provider.clone(),
            http_provider,
            elf,
            block_execution_strategy_factory,
            prover_client,
            (),
            config,
        )
        .await?,
    );

    let concurrent_executions_semaphore = Arc::new(Semaphore::new(args.max_concurrent_executions));

    let failed = Arc::new(AtomicBool::new(false));
    let mut block_number = args.block_number;

    info!("starting");

    loop {
        info!("process block: {:?}", block_number);

        let executor = executor.clone();
        let alerting_client = alerting_client.clone();
        let permit = concurrent_executions_semaphore.clone().acquire_owned().await?;
        let flag = Arc::clone(&failed);

        task::spawn(async move {
            match process_block(block_number, executor, args.execution_retries).await {
                Ok(_) => {
                    info!("Successfully processed block {block_number}");
                }
                Err(err) => {
                    let error_message = format!("Error executing block {block_number}: {err}");
                    error!("{error_message}");

                    if let Some(alerting_client) = &alerting_client {
                        alerting_client.send_alert(error_message).await;
                    }

                    flag.store(true, Ordering::Relaxed);
                }
            }

            drop(permit);
        });

        if failed.load(Ordering::Relaxed) {
            panic!("Exit due to the exit of the child thread");
        }

        block_number += 1;
    }
}

#[instrument(skip(executor, max_retries))]
async fn process_block<C, P>(
    number: u64,
    executor: Arc<FullExecutor<C, P>>,
    max_retries: usize,
) -> eyre::Result<()>
where
    C: ExecutorComponents<Network = Ethereum>,
    P: Provider<Ethereum> + Clone + std::fmt::Debug,
{
    // Wait for the block to be available in the HTTP provider
    let mut retry_count = 0;
    loop {
        match executor.wait_for_block(number).await {
            Ok(_) => break,
            Err(err) => {
                warn!("Failed to wait block {number}: {err}, retrying {retry_count}...");
                if retry_count > max_retries {
                    error!("Max retries {retry_count} reached for block: {number}");
                    return Err(err);
                }
                retry_count += 1;
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }

    let mut retry_count = 0;
    loop {
        match executor.execute(number).await {
            Ok(_) => {
                return Ok(());
            }
            Err(err) => {
                warn!("Failed to execute block {number}: {err}, retrying {retry_count}...");
                if retry_count > max_retries {
                    error!("Max retries {retry_count} reached for block: {number}");
                    return Err(err);
                }
                retry_count += 1;
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}
