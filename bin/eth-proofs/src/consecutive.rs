//! Bounded preparation of consecutive blocks with ordered, durable publication.
use futures::{channel::mpsc, pin_mut, SinkExt, Stream, StreamExt};
use std::{future::Future, time::Duration};
use tokio::sync::watch;

pub async fn run<S, P, PF, C, T>(
    blocks: S,
    concurrency: usize,
    mut output: mpsc::Sender<(u64, T)>,
    mut shutdown: watch::Receiver<bool>,
    mut prepare: P,
    mut persist: C,
) -> eyre::Result<()>
where
    S: Stream<Item = eyre::Result<u64>>,
    P: FnMut(u64) -> PF,
    PF: Future<Output = eyre::Result<T>>,
    C: FnMut(u64, &T) -> eyre::Result<()>,
{
    eyre::ensure!(concurrency > 0, "preparation concurrency must be positive");
    let prepared = blocks
        .map(move |number| {
            let pending = number.map(|number| (number, prepare(number)));
            async move {
                let (number, future) = pending?;
                Ok::<_, eyre::Report>((number, future.await?))
            }
        })
        .buffered(concurrency);
    pin_mut!(prepared);
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let next = tokio::select! {
            biased;
            _ = shutdown.changed() => return Ok(()),
            next = prepared.next() => next,
        };
        let Some(next) = next else { return Ok(()) };
        let (number, input) = next?;
        // Later completions cannot be persisted or published ahead of this block.
        persist(number, &input)?;
        tokio::select! {
            biased;
            _ = shutdown.changed() => return Ok(()),
            result = output.send((number, input)) => {
                if result.is_err() { return Ok(()) }
            },
        }
    }
}

/// A preparation failure occupies its original slot until the same block succeeds.
pub async fn retry<P, PF, E, EF, T>(
    number: u64,
    delay: Duration,
    mut prepare: P,
    mut on_error: E,
) -> T
where
    P: FnMut(u64) -> PF,
    PF: Future<Output = eyre::Result<T>>,
    E: FnMut(u64, eyre::Report) -> EF,
    EF: Future<Output = ()>,
{
    loop {
        match prepare(number).await {
            Ok(input) => return input,
            Err(error) => {
                on_error(number, error).await;
                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{stream, FutureExt};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn overlaps_preparation_but_persists_and_delivers_in_block_order() {
        let first = Arc::new(Semaphore::new(0));
        let second = Arc::new(Semaphore::new(0));
        let started = Arc::new(Mutex::new(Vec::new()));
        let finished = Arc::new(Mutex::new(Vec::new()));
        let persisted = Arc::new(Mutex::new(Vec::new()));
        let (tx, mut rx) = mpsc::channel(4);
        let (_stop, shutdown) = watch::channel(false);
        let task = tokio::spawn({
            let first = first.clone();
            let second = second.clone();
            let started = started.clone();
            let finished = finished.clone();
            let persisted = persisted.clone();
            async move {
                run(
                    stream::iter((100..104).map(Ok)),
                    2,
                    tx,
                    shutdown,
                    move |number| {
                        let first = first.clone();
                        let second = second.clone();
                        let started = started.clone();
                        let finished = finished.clone();
                        async move {
                            started.lock().unwrap().push(number);
                            if number == 100 {
                                first.acquire().await.unwrap().forget();
                            }
                            if number == 101 {
                                second.acquire().await.unwrap().forget();
                            }
                            finished.lock().unwrap().push(number);
                            Ok(number)
                        }
                    },
                    move |number, _| {
                        persisted.lock().unwrap().push(number);
                        Ok(())
                    },
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while started.lock().unwrap().len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(*started.lock().unwrap(), vec![100, 101]);
        second.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !finished.lock().unwrap().contains(&101) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(rx.next().now_or_never().is_none());
        assert!(persisted.lock().unwrap().is_empty());
        first.add_permits(1);
        let mut received = Vec::new();
        while let Some((number, value)) = rx.next().await {
            assert_eq!(number, value);
            received.push(number);
        }
        task.await.unwrap().unwrap();
        assert_eq!(received, vec![100, 101, 102, 103]);
        assert_eq!(*persisted.lock().unwrap(), received);
    }

    #[tokio::test]
    async fn retries_a_failed_block_before_delivering_its_ready_successor() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let failures = Arc::new(Mutex::new(Vec::new()));
        let (tx, mut rx) = mpsc::channel(4);
        let (_stop, shutdown) = watch::channel(false);
        let task = tokio::spawn({
            let attempts = attempts.clone();
            let failures = failures.clone();
            async move {
                run(
                    stream::iter([Ok(100), Ok(101)]),
                    2,
                    tx,
                    shutdown,
                    move |number| {
                        let attempts = attempts.clone();
                        let failures = failures.clone();
                        async move {
                            Ok(retry(
                                number,
                                Duration::from_millis(10),
                                move |number| {
                                    let failed = number == 100 &&
                                        attempts.fetch_add(1, Ordering::SeqCst) == 0;
                                    std::future::ready(if failed {
                                        Err(eyre::eyre!("witness unavailable"))
                                    } else {
                                        Ok(number)
                                    })
                                },
                                move |number, _| {
                                    failures.lock().unwrap().push(number);
                                    std::future::ready(())
                                },
                            )
                            .await)
                        }
                    },
                    |_, _| Ok(()),
                )
                .await
            }
        });
        assert_eq!(rx.next().await, Some((100, 100)));
        assert_eq!(rx.next().await, Some((101, 101)));
        task.await.unwrap().unwrap();
        assert_eq!(*failures.lock().unwrap(), vec![100]);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn shutdown_cancels_pending_work_without_persisting_later_results() {
        let started = Arc::new(AtomicUsize::new(0));
        let persisted = Arc::new(AtomicUsize::new(0));
        let (tx, _rx) = mpsc::channel(1);
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn({
            let started = started.clone();
            let persisted = persisted.clone();
            async move {
                run(
                    stream::iter((100..110).map(Ok)),
                    2,
                    tx,
                    shutdown,
                    move |number| {
                        started.fetch_add(1, Ordering::SeqCst);
                        async move {
                            if number == 100 {
                                std::future::pending::<()>().await;
                            }
                            Ok(number)
                        }
                    },
                    move |_, _| {
                        persisted.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while started.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap().unwrap();
        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert_eq!(persisted.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn paused_consumer_bounds_preparation_and_shutdown_interrupts_backpressure() {
        let started = Arc::new(AtomicUsize::new(0));
        let (tx, _rx) = mpsc::channel(1);
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn({
            let started = started.clone();
            async move {
                run(
                    stream::iter((100..200).map(Ok)),
                    2,
                    tx,
                    shutdown,
                    move |number| {
                        started.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Ok(number))
                    },
                    |_, _| Ok(()),
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while started.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(started.load(Ordering::SeqCst) <= 5, "producer ran past its bounded queue");
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap().unwrap();
    }
}
