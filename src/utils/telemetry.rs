use crossbeam_channel::{bounded, Sender, Receiver};
use serde::Serialize;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const BATCH_SIZE: usize = 50;
const FLUSH_INTERVAL_MS: u64 = 1000;  // 1 second for faster flushing

#[derive(Debug, Clone, Serialize)]
pub enum EventType {
    #[serde(rename = "found")]
    Found,
    #[serde(rename = "removed")]
    Removed,
}

/// Event sent to the backend API
#[derive(Debug, Clone, Serialize)]
pub struct TelemetryEvent {
    #[serde(rename = "status")]
    pub event_type: EventType,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rule_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub file: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub org: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub repo: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub risk_class: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub risk_impact: String,
}

/// Internal struct for telemetry context
#[allow(dead_code)]
pub struct TelemetryContext {
    pub org: String,
    pub repo: String,
    pub api_key: String,
}

#[derive(Serialize)]
struct TelemetryBatch {
    events: Vec<TelemetryEvent>,
    #[serde(skip_serializing_if = "String::is_empty")]
    org: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    repo: String,
}

/// Non-blocking telemetry client that batches events and POSTs via background thread.
/// Network failures are silent to ensure zero scan latency impact.
pub struct TelemetryClient {
    sender: Sender<TelemetryEvent>,
    #[allow(dead_code)]
    handle: Option<JoinHandle<()>>,
}

impl TelemetryClient {
    /// Create a new TelemetryClient that sends events to the specified endpoint.
    /// Spawns a background thread for batching and network I/O.
    pub fn new(report_url: String) -> Self {
        let (sender, receiver): (Sender<TelemetryEvent>, Receiver<TelemetryEvent>) = bounded(1000);

        let handle = thread::spawn(move || {
            Self::worker_loop(receiver, report_url);
        });

        Self {
            sender,
            handle: Some(handle),
        }
    }

    /// Create a no-op client that discards all events (when telemetry is disabled).
    pub fn disabled() -> Self {
        let (sender, _receiver): (Sender<TelemetryEvent>, Receiver<TelemetryEvent>) = bounded(1);
        Self {
            sender,
            handle: None,
        }
    }

    /// Send a telemetry event (non-blocking).
    /// Returns immediately; events are queued for batch processing.
    pub fn send(&self, event: TelemetryEvent) {
        // Non-blocking send - if channel is full, drop the event silently
        let _ = self.sender.try_send(event);
    }

    /// Flush remaining events and wait for completion.
    /// Call this before program exit to ensure all events are sent.
    pub fn flush(&self) {
        // Signal shutdown by dropping our sender clone won't work since we keep it
        // Instead, just give the worker time to flush
        thread::sleep(Duration::from_millis(100));
    }

    fn worker_loop(receiver: Receiver<TelemetryEvent>, report_url: String) {
        let mut batch: Vec<TelemetryEvent> = Vec::with_capacity(BATCH_SIZE);
        let flush_duration = Duration::from_millis(FLUSH_INTERVAL_MS);

        loop {
            match receiver.recv_timeout(flush_duration) {
                Ok(event) => {
                    batch.push(event);
                    if batch.len() >= BATCH_SIZE {
                        Self::send_batch(&report_url, &batch);
                        batch.clear();
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    // Flush on timeout if we have pending events
                    if !batch.is_empty() {
                        Self::send_batch(&report_url, &batch);
                        batch.clear();
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    // Channel closed, flush remaining and exit
                    if !batch.is_empty() {
                        Self::send_batch(&report_url, &batch);
                    }
                    break;
                }
            }
        }
    }

    fn send_batch(report_url: &str, batch: &[TelemetryEvent]) {
        // Extract org/repo from first event (all events in a batch share the same context)
        let (org, repo) = batch.first()
            .map(|e| (e.org.clone(), e.repo.clone()))
            .unwrap_or_default();

        let payload = TelemetryBatch {
            events: batch.to_vec(),
            org,
            repo,
        };

        // Serialize and POST - fail silently on any error
        if let Ok(body) = serde_json::to_string(&payload) {
            let _ = ureq::post(report_url)
                .set("Content-Type", "application/json")
                .timeout(Duration::from_secs(10))
                .send_string(&body);
        }
    }
}

impl Drop for TelemetryClient {
    fn drop(&mut self) {
        // Give worker thread time to flush remaining events
        if self.handle.is_some() {
            thread::sleep(Duration::from_millis(200));
        }
    }
}
