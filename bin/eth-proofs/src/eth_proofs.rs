use crate::state::State;
use std::{sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::eyre;
use host_executor::ExecutionHooks;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use tracing::{error, info};
use zkm_sdk::{HashableKey, ZKMVerifyingKey};

#[derive(Clone)]
pub struct EthProofsClient {
    cluster_id: u64,
    endpoint: String,
    api_token: String,
    client: ClientWithMiddleware,
    state: Option<Arc<State>>,
}

impl EthProofsClient {
    pub fn new(cluster_id: u64, endpoint: String, api_token: String) -> Self {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
        let client = ClientBuilder::new(
            reqwest::Client::builder().timeout(Duration::from_secs(60)).build().unwrap(),
        )
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build();

        Self { cluster_id, endpoint, api_token, client, state: None }
    }

    pub fn with_state(mut self, state: Arc<State>) -> Self {
        self.state = Some(state);
        self
    }

    pub fn start_reporter(&self) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let Some(state) = &this.state else {
                return;
            };
            loop {
                match state.pending() {
                    Ok(pending) => {
                        for (block, payload) in pending {
                            let result = this
                                .client
                                .post(format!("{}/proofs/proved", this.endpoint))
                                .header("Authorization", format!("Bearer {}", this.api_token))
                                .json(&payload)
                                .send()
                                .await;
                            match result {
                                Ok(response) if response.status().is_success() => {
                                    if let Err(err) = state.acknowledge(block) {
                                        error!(block, %err, "report accepted but acknowledgment persistence failed");
                                    } else {
                                        info!(block, "durable EthProofs report acknowledged");
                                    }
                                }
                                Ok(response) => {
                                    error!(block, status = %response.status(), "EthProofs report remains pending")
                                }
                                Err(err) => error!(block, %err, "EthProofs report remains pending"),
                            }
                        }
                    }
                    Err(err) => error!(%err, "reading persistent reporting outbox failed"),
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        })
    }

    pub async fn queued(&self, block_number: u64) {
        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
        });

        let this = self.clone();

        // Spawn another task to avoid retries to impact block execution
        tokio::spawn(async move {
            let response = this
                .client
                .post(format!("{}/proofs/queued", this.endpoint))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", this.api_token))
                .json(&json)
                .send()
                .await
                .map_err(|e| eyre!(e))
                .and_then(|r| r.error_for_status().map_err(|e| eyre!(e)));

            if let Err(err) = response {
                error!("Failed to report proof queuing: {}", err)
            }
        });
    }

    pub async fn proving(&self, block_number: u64) {
        let json = serde_json::json!({
            "block_number": block_number,
            "cluster_id": self.cluster_id,
        });
        let this = self.clone();

        // Spawn another task to avoid retries to impact block execution
        tokio::spawn(async move {
            let response = this
                .client
                .post(format!("{}/proofs/proving", this.endpoint))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", this.api_token))
                .json(&json)
                .send()
                .await
                .map_err(|e| eyre!(e))
                .and_then(|r| r.error_for_status().map_err(|e| eyre!(e)));

            if let Err(err) = response {
                error!("Failed to report proof proving: {}", err)
            }
        });
    }

    pub async fn proved(
        &self,
        proof_bytes: &[u8],
        block_number: u64,
        cycles: u64,
        elapsed: f32,
        vk: &ZKMVerifyingKey,
    ) {
        let json = serde_json::json!({
            "proof": STANDARD.encode(proof_bytes),
            "block_number": block_number,
            "proving_cycles": cycles,
            "proving_time": (elapsed * 1000.0) as u64,
            "verifier_id": vk.bytes32(),
            "cluster_id": self.cluster_id,
        });

        let this = self.clone();

        // Spawn another task to avoid retries to impact block execution
        tokio::spawn(async move {
            // Submit proof to the API

            let response = this
                .client
                .post(format!("{}/proofs/proved", this.endpoint))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", this.api_token))
                .json(&json)
                .send()
                .await
                .map_err(|e| eyre!(e))
                .and_then(|r| r.error_for_status().map_err(|e| eyre!(e)));

            match response {
                Ok(_) => info!(
                    "Reported proved block {} to eth-proofs: {} cycles, {:.1} s",
                    block_number, cycles, elapsed
                ),
                Err(err) => error!("Failed to report proof proved: {}", err),
            }
        });
    }
}

impl ExecutionHooks for EthProofsClient {
    async fn on_execution_start(&self, block_number: u64) -> eyre::Result<()> {
        #[cfg(not(feature = "test"))]
        self.queued(block_number).await;

        Ok(())
    }

    async fn on_proving_start(&self, block_number: u64) -> eyre::Result<()> {
        #[cfg(not(feature = "test"))]
        self.proving(block_number).await;

        Ok(())
    }

    async fn on_proving_end(
        &self,
        block_number: u64,
        proof_bytes: &[u8],
        _public_values_bytes: &[u8],
        _zkm_version: &str,
        vk: &ZKMVerifyingKey,
        cycles: u64,
        proving_duration: Duration,
    ) -> eyre::Result<()> {
        if let Some(state) = &self.state {
            let payload = serde_json::json!({
                "proof": STANDARD.encode(proof_bytes), "block_number": block_number,
                "proving_cycles": cycles, "proving_time": proving_duration.as_millis() as u64,
                "verifier_id": vk.bytes32(), "cluster_id": self.cluster_id,
            });
            // Commit the output and its retryable report before the cursor advances.
            state.commit(block_number, proof_bytes, _public_values_bytes, payload)?;
        } else {
            #[cfg(not(feature = "test"))]
            self.proved(proof_bytes, block_number, cycles, proving_duration.as_secs_f32(), vk)
                .await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Identity;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn report_is_retained_until_http_success() {
        let root = tempfile::tempdir().unwrap();
        let state = Arc::new(
            State::open(
                root.path(),
                Identity {
                    namespace: "test".into(),
                    tenant: "ethproofs".into(),
                    chain_id: 1,
                    cluster_id: 8,
                    elf_id: "elf".into(),
                    interval: 1,
                    residue: 0,
                },
                Some(10),
            )
            .unwrap(),
        );
        state.commit(10, b"proof", b"values", serde_json::json!({"block_number":10})).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = EthProofsClient::new(
            8,
            format!("http://{}", listener.local_addr().unwrap()),
            "test".into(),
        )
        .with_state(state.clone());
        let reporter = client.start_reporter();
        for status in ["401 Unauthorized", "200 OK"] {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut bytes = [0; 2048];
                let n = socket.read(&mut bytes).await.unwrap();
                request.extend_from_slice(&bytes[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
                assert!(n > 0);
            }
            assert!(String::from_utf8_lossy(&request).starts_with("POST /proofs/proved"));
            assert_eq!(state.pending_count().unwrap(), 1);
            socket
                .write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while state.pending_count().unwrap() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        reporter.abort();
        let _ = reporter.await;
        drop(client);
        drop(state);
        let restored = State::open(
            root.path(),
            Identity {
                namespace: "test".into(),
                tenant: "ethproofs".into(),
                chain_id: 1,
                cluster_id: 8,
                elf_id: "elf".into(),
                interval: 1,
                residue: 0,
            },
            None,
        )
        .unwrap();
        assert_eq!(restored.pending_count().unwrap(), 0);
    }
}
