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
use futures::{channel::mpsc, future::ready, FutureExt, StreamExt};
use host_executor::{
    alerting::AlertingClient, create_eth_block_execution_strategy_factory, EthExecutorComponents,
    FullExecutor,
};
use provider::create_provider;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use zkm_sdk::{include_elf, ProverClient};

mod cli;
mod consecutive;
mod latest;
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
        (1..=2).contains(&args.prepare_concurrency) && args.prefetch_depth > 0,
        "preparation concurrency must be 1 or 2 and queue depth must be positive"
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
    eyre::ensure!(!args.latest_block || state.is_some(), "--latest-block requires local mode");
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
    let stream = if state.is_some() {
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
    let (tx, mut rx) = mpsc::channel(args.prefetch_depth.max(1));
    let (latest_tx, mut latest_rx) = tokio::sync::watch::channel(None);
    // Recover a completed proof before choosing a fresh head. Only this prover
    // owns the durable cursor; preparations never advance or delete its inputs.
    if args.latest_block {
        let state = state.as_ref().unwrap();
        if let Some(number) = state.next_block() {
            if state.is_committed(number)? {
                state.advance(number, true)?;
            }
        }
    }
    let mut fetcher = {
        let executor = executor.clone();
        let alerting_client = alerting_client.clone();
        let max_lag = args.max_lag;
        let state = state.clone();
        let preparation_shutdown = shutdown.clone();
        let latest_block = args.latest_block;
        let head_provider = http_provider.clone();
        let prepare_concurrency = args.prepare_concurrency;
        tokio::spawn(async move {
            if latest_block {
                let minimum = state.as_ref().unwrap().next_block().unwrap_or(0);
                return latest::run(
                    prepare_concurrency,
                    minimum,
                    block_interval,
                    block_residue,
                    latest_tx,
                    preparation_shutdown,
                    || {
                        let provider = head_provider.clone();
                        async move { Ok(provider.get_block_number().await?) }
                    },
                    |number| {
                        let executor = executor.clone();
                        async move {
                            executor.wait_for_block(number).await?;
                            let input = executor.prepare(number).await?;
                            Ok(Arc::new(bincode::serialize(&input)?))
                        }
                    },
                )
                .await;
            }
            // Headers bound how far ahead we may prepare. The durable cursor is
            // advanced only by the prover, after committing each ordered output.
            let next = state.as_ref().and_then(|s| s.next_block()).unwrap_or(0);
            let blocks = futures::stream::try_unfold((0u64, next, stream), {
                let state = state.clone();
                move |(mut head, mut next, mut stream)| {
                    let state = state.clone();
                    async move {
                        loop {
                            if next == 0 || next > head {
                                match stream.next().await {
                                    Some(header) => {
                                        head = head.max(header);
                                        if next == 0 {
                                            next = header -
                                                ((header + block_interval - block_residue) %
                                                    block_interval);
                                            if let Some(state) = &state {
                                                state.initialize(next)?;
                                            }
                                        }
                                        continue;
                                    }
                                    None => return Ok::<_, eyre::Report>(None),
                                }
                            }
                            while let Some(Some(header)) = stream.next().now_or_never() {
                                head = head.max(header);
                            }
                            let number = next;
                            next = next
                                .checked_add(block_interval)
                                .ok_or_else(|| eyre::eyre!("preparation block cursor overflow"))?;
                            if max_lag > 0 && head - number > max_lag {
                                warn!(
                                    "skipping block {number}: {} behind the newest header",
                                    head - number
                                );
                                continue;
                            }
                            return Ok(Some((number, (head, next, stream))));
                        }
                    }
                }
            })
            .boxed();
            let persist_state = state.clone();
            consecutive::run(
                blocks,
                prepare_concurrency,
                tx,
                preparation_shutdown,
                move |number| {
                    let executor = executor.clone();
                    let state = state.clone();
                    let alerting_client = alerting_client.clone();
                    async move {
                        if let Some(state) = &state {
                            if state.is_committed(number)? {
                                return Ok(None);
                            }
                            if let Some(bytes) = state.input(number)? {
                                return Ok(Some(bincode::deserialize(&bytes)?));
                            }
                        }
                        let input = consecutive::retry(
                            number,
                            Duration::from_secs(5),
                            move |number| {
                                let executor = executor.clone();
                                async move {
                                    executor.wait_for_block(number).await?;
                                    executor.prepare(number).await
                                }
                            },
                            move |number, err| {
                                let alerting_client = alerting_client.clone();
                                async move { report_error(&alerting_client, number, err).await }
                            },
                        )
                        .await;
                        Ok(Some(input))
                    }
                    .boxed()
                },
                move |number, input| {
                    if let (Some(state), Some(input)) = (&persist_state, input) {
                        state.save_input(number, &bincode::serialize(input)?)?;
                    }
                    Ok(())
                },
            )
            .await
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
        let next = if args.latest_block {
            loop {
                let prepared = latest_rx.borrow_and_update().clone();
                if let Some((number, bytes)) = prepared {
                    let state = state.as_ref().unwrap();
                    if state.next_block().is_none_or(|next| number >= next) {
                        state.initialize(number)?;
                        let next = state.next_block().unwrap();
                        if number > next {
                            warn!(
                                from = next,
                                to = number,
                                "skipping lagging blocks to newest prepared head"
                            );
                            state.skip_to(number)?;
                        }
                        state.save_input(number, &bytes)?;
                        break Some((number, Some(bincode::deserialize(&bytes)?)));
                    }
                }
                tokio::select! {
                    changed = latest_rx.changed() => {
                        if changed.is_err() { break None; }
                    },
                    _ = shutdown.changed() => break None,
                }
            }
        } else {
            tokio::select! {
                next = rx.next() => next,
                _ = shutdown.changed(), if state.is_some() => None,
            }
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
                        fetcher.abort();
                        let _ = (&mut fetcher).await;
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
        let _ = fetcher.await;
    } else {
        fetcher.await??;
    }
    reporter.abort();
    if state.is_some() && !*shutdown.borrow() {
        eyre::bail!("local worker preparation stream ended unexpectedly");
    }

    Ok(())
}

fn latest_selected_block(head: u64, interval: u64, residue: u64) -> Option<u64> {
    let remainder = head % interval;
    let distance =
        if remainder >= residue { remainder - residue } else { interval - (residue - remainder) };
    head.checked_sub(distance)
}

#[cfg(test)]
mod selection_tests {
    use super::latest_selected_block;

    #[test]
    fn newest_selection_aligns_to_the_stream_and_handles_early_heads() {
        assert_eq!(latest_selected_block(123, 1, 0), Some(123));
        assert_eq!(latest_selected_block(100, 10, 2), Some(92));
        assert_eq!(latest_selected_block(103, 10, 2), Some(102));
        assert_eq!(latest_selected_block(1, 10, 2), None);
        assert_eq!(latest_selected_block(u64::MAX, u64::MAX, u64::MAX - 1), Some(u64::MAX - 1));
    }
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
