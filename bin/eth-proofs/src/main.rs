use sha2::{Digest, Sha256};
use state::{Identity, State};
use std::{env, sync::Arc, time::Duration};
use zkm_cuda::ZKMGpuServer;
use zkm_prover::ZKMProver;
use zkm_sdk::provers::CudaProver;

use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use clap::Parser;
use cli::Args;
use eth_proofs::EthProofsClient;
use futures::{channel::mpsc, future::ready, FutureExt, SinkExt, StreamExt};
use host_executor::{
    alerting::AlertingClient, create_eth_block_execution_strategy_factory, EthExecutorComponents,
    FullExecutor,
};
use provider::create_provider;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use zkm_sdk::{include_elf, ProverClient};

mod cli;
mod state;

mod eth_proofs;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    exit_with_parent()?;
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
                .add_directive("zkm_core_executor=warn".parse().unwrap())
                .add_directive("zkm_prover=warn".parse().unwrap())
                .add_directive("zkm_sdk=info".parse().unwrap()),
        )
        .init();

    // Parse the command line arguments.
    let args = Args::parse();
    let config = args.as_config().await?;

    eyre::ensure!(args.block_interval > 0, "block interval must be positive");
    eyre::ensure!(args.max_pending_reports > 0, "pending report limit must be positive");
    eyre::ensure!(
        args.prepare_concurrency == 1 && args.prefetch_depth > 0,
        "this migration starts with serial preparation and a positive queue depth"
    );
    let elf = match &args.elf_file {
        Some(path) => std::fs::read(path)?,
        None => include_elf!("reth").to_vec(),
    };
    let elf_id = hex::encode(Sha256::digest(&elf));
    if let Some(expected) = &args.expected_elf_id {
        eyre::ensure!(*expected == elf_id, "guest ELF differs from the app's configured digest");
    }
    let state = if let Some(endpoint) = &args.local_gpu_endpoint {
        eyre::ensure!(
            endpoint.scheme() == "http" &&
                matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
            "local GPU endpoint must be loopback HTTP"
        );
        eyre::ensure!(
            !args.execute_only && args.max_lag == 0,
            "durable local mode requires proving and never skips lagging blocks"
        );
        let root = args
            .state_dir
            .as_ref()
            .ok_or_else(|| eyre::eyre!("local proving requires --state-dir"))?;
        eyre::ensure!(args.expected_elf_id.is_some(), "local proving requires --expected-elf-id");
        let state = Arc::new(State::open(
            root,
            Identity {
                namespace: std::env::var("FLEET_APP_NAMESPACE")?,
                tenant: std::env::var("FLEET_APP_TENANT")?,
                chain_id: 1,
                cluster_id: args.eth_proofs_cluster_id,
                elf_id: elf_id.clone(),
                interval: args.block_interval,
                residue: args.block_residue % args.block_interval,
            },
            args.start_block,
        )?);
        // FullExecutor's verification-key file belongs to this replica's storage.
        std::env::set_current_dir(std::fs::canonicalize(root)?)?;
        Some(state)
    } else {
        eyre::ensure!(args.state_dir.is_none(), "durable worker state requires local proving");
        None
    };
    info!(%elf_id, local = state.is_some(), "starting EthProofs app pipeline");
    let block_execution_strategy_factory =
        create_eth_block_execution_strategy_factory(&config.genesis, None);

    let eth_proofs_client = EthProofsClient::new(
        args.eth_proofs_cluster_id,
        args.eth_proofs_endpoint,
        args.eth_proofs_api_token,
    );
    let eth_proofs_client = match &state {
        Some(state) => eth_proofs_client.with_state(state.clone()),
        None => eth_proofs_client,
    };
    let reporter = eth_proofs_client.start_reporter();
    let (shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);
    if state.is_some() {
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                let mut terminate =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .unwrap();
                tokio::select! { _ = terminate.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            info!("draining EthProofs worker; finish the current proof and persist its cursor");
            let _ = shutdown_tx.send(true);
        });
    }

    let alerting_client = args.pager_duty_integration_key.map(AlertingClient::new);

    let http_provider = create_provider(args.http_rpc_url);
    let debug_http_provider = create_provider(args.debug_http_rpc_url);
    eyre::ensure!(
        http_provider.get_chain_id().await? == 1,
        "EthProofs worker requires Ethereum mainnet RPC"
    );
    let block_interval = args.block_interval;
    let block_residue = args.block_residue % block_interval;
    // Local mode uses HTTP head polling: a WS disconnect cannot discard the cursor.
    let ws_provider = if state.is_none() {
        #[allow(deprecated)]
        let provider = ProviderBuilder::new()
            .on_ws(WsConnect::new(
                args.ws_rpc_url
                    .ok_or_else(|| eyre::eyre!("network proving requires --ws-rpc-url"))?,
            ))
            .await?;
        Some(provider)
    } else {
        None
    };
    let head_shutdown = shutdown.clone();
    let mut stream = if state.is_some() {
        futures::stream::unfold(
            (http_provider.clone(), None, head_shutdown),
            |(provider, mut previous, shutdown)| async move {
                loop {
                    if *shutdown.borrow() {
                        return None;
                    }
                    match provider.get_block_number().await {
                        Ok(head) if previous != Some(head) => {
                            previous = Some(head);
                            return Some((head, (provider, previous, shutdown)));
                        }
                        Ok(_) => {}
                        Err(err) => {
                            warn!(%err, "head RPC failed; retrying without advancing cursor")
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            },
        )
        .boxed()
    } else {
        ws_provider
            .as_ref()
            .unwrap()
            .subscribe_blocks()
            .await?
            .into_stream()
            .filter(move |h| ready(h.number % block_interval == block_residue))
            .map(|h| h.number)
            .boxed()
    };
    let client = if let Some(endpoint) = args.local_gpu_endpoint {
        let endpoint = endpoint.to_string();
        Arc::new(
            tokio::task::spawn_blocking(move || ProverClient {
                prover: Box::new(CudaProver::new(
                    ZKMProver::new(),
                    ZKMGpuServer::External { endpoint },
                )),
            })
            .await?,
        )
    } else {
        Arc::new(ProverClient::new())
    };

    let executor = FullExecutor::<EthExecutorComponents<_, _>, _>::try_new(
        http_provider.clone(),
        debug_http_provider.clone(),
        elf,
        block_execution_strategy_factory,
        client,
        eth_proofs_client,
        config,
    )
    .await?;

    info!("Latest block number: {}", http_provider.get_block_number().await?);

    // Two-stage pipeline.  The fetcher pulls headers off the subscription,
    // fetches the block + witness and runs the native execution; the prover
    // loop below consumes the prepared inputs one at a time.  Block N+1's
    // fetch therefore overlaps block N's proof instead of leaving the cards
    // idle for the RPC round trips.
    let executor = Arc::new(executor);
    let alerting_client = Arc::new(alerting_client);
    let (mut tx, mut rx) = mpsc::channel(args.prefetch_depth.max(1));
    let fetcher = {
        let executor = executor.clone();
        let alerting_client = alerting_client.clone();
        let max_lag = args.max_lag;
        let state = state.clone();
        let preparation_shutdown = shutdown.clone();
        tokio::spawn(async move {
            // The subscription is only a wake-up: it says how far the chain
            // is.  Which block to prepare next is a cursor that advances by
            // `block_interval`, so falling behind never skips a block — the
            // backlog is worked through in order (unless `max_lag` says to
            // drop it).  A header stream that lags drops headers; the cursor
            // does not.
            let mut head = 0u64;
            let mut next = state.as_ref().and_then(|s| s.next_block()).unwrap_or(0);
            loop {
                if *preparation_shutdown.borrow() {
                    break;
                }
                if next == 0 || next > head {
                    match stream.next().await {
                        Some(header) => {
                            head = head.max(header);
                            if next == 0 {
                                // The stream only delivers this instance's
                                // residue class, so the cursor starts aligned.
                                next = header -
                                    ((header + block_interval - block_residue) % block_interval);
                                if let Some(state) = &state {
                                    state.initialize(next)?;
                                }
                            }
                            continue;
                        }
                        None => break,
                    }
                }
                // Absorb whatever headers are already queued so `head` is fresh.
                while let Some(Some(header)) = stream.next().now_or_never() {
                    head = head.max(header);
                }

                let number = next;
                next += block_interval;
                if max_lag > 0 && head - number > max_lag {
                    warn!("skipping block {number}: {} behind the newest header", head - number);
                    continue;
                }

                if let Some(state) = &state {
                    if state.is_committed(number)? {
                        if tx.send((number, None)).await.is_err() {
                            break;
                        }
                        continue;
                    }
                }
                // Retry the same block; a transient preparation failure must not skip it.
                loop {
                    let prepared = match executor.wait_for_block(number).await {
                        Ok(()) => {
                            if let Some(state) = &state {
                                match state.input(number)? {
                                    Some(bytes) => Ok(bincode::deserialize(&bytes)?),
                                    None => executor.prepare(number).await,
                                }
                            } else {
                                executor.prepare(number).await
                            }
                        }
                        Err(err) => Err(err),
                    };
                    match prepared {
                        Ok(client_input) => {
                            if let Some(state) = &state {
                                state.save_input(number, &bincode::serialize(&client_input)?)?;
                            }
                            if tx.send((number, Some(client_input))).await.is_err() {
                                return Ok::<(), eyre::Report>(());
                            }
                            break;
                        }
                        Err(err) => {
                            report_error(&alerting_client, number, err).await;
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                }
            }
            Ok::<(), eyre::Report>(())
        })
    };

    // NOT pipelined, deliberately.  Sending block N+1's request early is
    // worth ~0.3 s of transfer per block, but the server parks a session
    // guard between a block's core and its compress and a new core request
    // drops it: a request that lands in that window lets two blocks
    // interleave on one card, which is what the guard is there to stop.
    'worker: loop {
        if *shutdown.borrow() {
            break;
        }
        let next = tokio::select! {
            next = rx.next() => next,
            _ = shutdown.changed(), if state.is_some() => None,
        };
        let Some((number, client_input)) = next else {
            break;
        };
        if let Some(state) = &state {
            while state.pending_count()? >= args.max_pending_reports {
                warn!(number, "report outbox full; waiting before starting another proof");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(3)) => {},
                    _ = shutdown.changed() => break,
                }
            }
            if *shutdown.borrow() {
                break;
            }
        }
        if let Some(client_input) = client_input {
            let committed =
                state.as_ref().map(|s| s.is_committed(number)).transpose()?.unwrap_or(false);
            if !committed {
                if let Some(state) = &state {
                    let block = loop {
                        let result = tokio::select! {
                            block = http_provider.get_block_by_number(number.into()) => block,
                            _ = shutdown.changed() => break 'worker,
                        };
                        match result {
                            Ok(Some(block)) => break block,
                            Ok(None) => warn!(number, "waiting for prepared block to be available"),
                            Err(err) => {
                                warn!(number, %err, "canonical block lookup failed; retrying")
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    };
                    if block.header.hash != client_input.current_block.header.hash_slow() {
                        state.discard_inputs_from(number)?;
                        eyre::bail!(
                            "prepared inputs invalidated by a reorg; restart from durable cursor"
                        );
                    }
                }
                if let Err(err) = executor.prove_prepared(client_input).await {
                    report_error(&alerting_client, number, err).await;
                    // The replica lifecycle recovers failed GPU servers; input stays durable.
                    if state.is_some() {
                        return Err(eyre::eyre!(
                            "local proof failed; durable input retained for restart"
                        ));
                    }
                }
            }
        }
        if let Some(state) = &state {
            state.advance(number, true)?;
        }
    }
    if *shutdown.borrow() {
        fetcher.abort();
    } else {
        fetcher.await??;
    }
    reporter.abort();
    if state.is_some() && !*shutdown.borrow() {
        eyre::bail!("local worker preparation stream ended unexpectedly");
    }

    Ok(())
}

async fn report_error(alerting_client: &Option<AlertingClient>, number: u64, err: eyre::Report) {
    let error_message = format!("Error handling block {number}: {err}");
    error!(error_message);

    if let Some(alerting_client) = alerting_client {
        alerting_client.send_alert(error_message).await;
    }
}

/// Actor death must not leave an orphan holding the durable stream lock.
fn exit_with_parent() -> eyre::Result<()> {
    if env::var("FLEET_EXIT_WITH_PARENT").as_deref() != Ok("true") {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let parent = libc::getppid();
        eyre::ensure!(parent > 1, "Fleet worker has no live parent");
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        eyre::ensure!(libc::getppid() == parent, "Fleet parent exited during startup");
    }
    Ok(())
}
