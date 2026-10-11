//! A bounded latest-head preparation pool. The prover consumes a single slot;
//! older completions cannot replace newer ones, even when RPCs finish out of order.
use futures::{stream::FuturesUnordered, StreamExt};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::sync::watch;
use tracing::{info, warn};

pub type Prepared = (u64, Arc<Vec<u8>>);

pub async fn run<H, HF, P, PF>(
    concurrency: usize,
    minimum: u64,
    interval: u64,
    residue: u64,
    output: watch::Sender<Option<Prepared>>,
    mut shutdown: watch::Receiver<bool>,
    mut head: H,
    mut prepare: P,
) -> eyre::Result<()>
where
    H: FnMut() -> HF,
    HF: Future<Output = eyre::Result<u64>>,
    P: FnMut(u64) -> PF,
    PF: Future<Output = eyre::Result<Arc<Vec<u8>>>>,
{
    eyre::ensure!(concurrency > 0 && interval > 0, "invalid preparation limits");
    let mut running = FuturesUnordered::new();
    let mut selected = None;
    let mut published = None;
    let mut poll = tokio::time::interval(Duration::from_millis(500));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if *shutdown.borrow() || output.is_closed() {
            break;
        }
        tokio::select! {
            _ = shutdown.changed() => break,
            result = running.next(), if !running.is_empty() => {
                if let Some((number, result)) = result {
                    match result {
                        Ok(bytes) if published.is_none_or(|previous| number > previous) => {
                            info!(number, "latest-head witness ready");
                            published = Some(number);
                            output.send_replace(Some((number, bytes)));
                        },
                        Ok(_) => {}, // A slower older witness must never replace a newer one.
                        Err(err) => warn!(number, %err, "latest-head witness preparation failed"),
                    }
                }
            },
            head_result = async { poll.tick().await; head().await }, if running.len() < concurrency => {
                let newest = match head_result {
                    Ok(head) => super::latest_selected_block(head, interval, residue),
                    Err(err) => {
                        warn!(%err, "latest head lookup failed; retrying");
                        continue;
                    }
                };
                if let Some(number) = newest.filter(|number| {
                    *number >= minimum && selected.is_none_or(|previous| *number > previous)
                }) {
                    selected = Some(number);
                    let future = prepare(number);
                    running.push(async move { (number, future.await) });
                    info!(number, active = running.len(), "latest-head witness preparation started");
                }
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn overlaps_two_preparations_and_keeps_newest_out_of_order_completion() {
        let head = Arc::new(AtomicU64::new(100));
        let active = Arc::new(AtomicUsize::new(0));
        let first = Arc::new(Semaphore::new(0));
        let second = Arc::new(Semaphore::new(0));
        let (output, mut ready) = watch::channel(None);
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn({
            let head = head.clone();
            let active = active.clone();
            let first = first.clone();
            let second = second.clone();
            async move {
                run(
                    2,
                    100,
                    1,
                    0,
                    output,
                    shutdown,
                    || std::future::ready(Ok(head.load(Ordering::SeqCst))),
                    |number| {
                        let active = active.clone();
                        let gate = if number == 100 { first.clone() } else { second.clone() };
                        async move {
                            active.fetch_add(1, Ordering::SeqCst);
                            let _permit = gate.acquire().await.unwrap();
                            active.fetch_sub(1, Ordering::SeqCst);
                            Ok(Arc::new(vec![number as u8]))
                        }
                    },
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            while active.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
            head.store(101, Ordering::SeqCst);
            while active.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
            // Both slots are occupied. Advancing the head must not start a third job.
            head.store(102, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(550)).await;
            assert_eq!(active.load(Ordering::SeqCst), 2);
            head.store(101, Ordering::SeqCst);
            second.add_permits(1);
            ready.changed().await.unwrap();
            assert_eq!(ready.borrow_and_update().as_ref().unwrap().0, 101);
            first.add_permits(1);
            while active.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert_eq!(ready.borrow().as_ref().unwrap().0, 101);
            assert!(!ready.has_changed().unwrap());
        })
        .await
        .unwrap();
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn replaces_waiting_witness_instead_of_building_a_backlog() {
        let head = Arc::new(AtomicU64::new(100));
        let (output, mut ready) = watch::channel(None);
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn({
            let head = head.clone();
            async move {
                run(
                    2,
                    100,
                    1,
                    0,
                    output,
                    shutdown,
                    || std::future::ready(Ok(head.load(Ordering::SeqCst))),
                    |number| std::future::ready(Ok(Arc::new(vec![number as u8]))),
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            ready.changed().await.unwrap();
            assert_eq!(ready.borrow_and_update().as_ref().unwrap().0, 100);
            // Simulate a busy prover: no receive while new heads are prepared.
            head.store(105, Ordering::SeqCst);
            ready.changed().await.unwrap();
            assert_eq!(ready.borrow_and_update().as_ref().unwrap().0, 105);
            head.store(110, Ordering::SeqCst);
            ready.changed().await.unwrap();
            assert_eq!(ready.borrow_and_update().as_ref().unwrap().0, 110);
        })
        .await
        .unwrap();
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
}
