use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use crossbeam_channel::{bounded, Receiver, Sender};
use crate::types::IngestFormat;

#[derive(Debug, Default)]
pub struct IngestMetrics {
    pub total_batches_ingested: AtomicU64,
    pub total_records_ingested: AtomicU64,
    pub total_bytes_ingested: AtomicU64,
    pub total_backpressure_events: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct BatchResult {
    pub records_processed: usize,
    pub bytes_processed: usize,
    pub duration_ns: u64,
}

pub struct BatchIngressController {
    worker_senders: Vec<Sender<Vec<u8>>>,
    worker_handles: Vec<JoinHandle<()>>,
    metrics: Arc<IngestMetrics>,
    is_running: Arc<AtomicBool>,
    next_worker: AtomicU64,
}

impl BatchIngressController {
    pub fn new(
        num_workers: usize,
        queue_capacity: usize,
        processor_fn: Arc<dyn Fn(Vec<u8>) + Send + Sync + 'static>,
    ) -> Self {
        let mut senders = Vec::with_capacity(num_workers);
        let mut handles = Vec::with_capacity(num_workers);
        let is_running = Arc::new(AtomicBool::new(true));
        let metrics = Arc::new(IngestMetrics::default());

        for _ in 0..num_workers {
            let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = bounded(queue_capacity);
            senders.push(tx);

            let proc = Arc::clone(&processor_fn);
            let running = Arc::clone(&is_running);

            let handle = thread::spawn(move || {
                while running.load(Ordering::Acquire) || !rx.is_empty() {
                    match rx.recv_timeout(std::time::Duration::from_millis(50)) {
                        Ok(record) => {
                            proc(record);
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    }
                }
            });

            handles.push(handle);
        }

        Self {
            worker_senders: senders,
            worker_handles: handles,
            metrics,
            is_running,
            next_worker: AtomicU64::new(0),
        }
    }

    /// Ingests a raw wire buffer, splits on record boundaries, and dispatches to workers via ring-buffer
    pub fn ingest_batch(&self, bytes: &[u8], format: IngestFormat) -> BatchResult {
        let start = std::time::Instant::now();
        let mut record_count = 0;
        let total_bytes = bytes.len();

        match format {
            IngestFormat::NdJson => {
                let mut start_idx = 0;
                for i in 0..bytes.len() {
                    if bytes[i] == b'\n' {
                        if i > start_idx {
                            let slice = &bytes[start_idx..i];
                            // Skip empty lines or pure whitespace
                            if !slice.iter().all(|&b| b == b' ' || b == b'\r' || b == b'\t') {
                                self.dispatch_record(slice.to_vec());
                                record_count += 1;
                            }
                        }
                        start_idx = i + 1;
                    }
                }
                // Trailing record if no trailing newline
                if start_idx < bytes.len() {
                    let slice = &bytes[start_idx..];
                    if !slice.iter().all(|&b| b == b' ' || b == b'\r' || b == b'\t') {
                        self.dispatch_record(slice.to_vec());
                        record_count += 1;
                    }
                }
            }
            IngestFormat::LengthPrefixed => {
                let mut cursor = 0;
                while cursor + 4 <= bytes.len() {
                    let len = u32::from_be_bytes([
                        bytes[cursor],
                        bytes[cursor + 1],
                        bytes[cursor + 2],
                        bytes[cursor + 3],
                    ]) as usize;
                    cursor += 4;
                    if cursor + len <= bytes.len() {
                        let slice = &bytes[cursor..cursor + len];
                        self.dispatch_record(slice.to_vec());
                        record_count += 1;
                        cursor += len;
                    } else {
                        break;
                    }
                }
            }
            IngestFormat::RawJson | IngestFormat::JsonArray => {
                // If single or entire array payload, dispatch as one unit
                self.dispatch_record(bytes.to_vec());
                record_count += 1;
            }
        }

        self.metrics
            .total_batches_ingested
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .total_records_ingested
            .fetch_add(record_count as u64, Ordering::Relaxed);
        self.metrics
            .total_bytes_ingested
            .fetch_add(total_bytes as u64, Ordering::Relaxed);

        BatchResult {
            records_processed: record_count,
            bytes_processed: total_bytes,
            duration_ns: start.elapsed().as_nanos() as u64,
        }
    }

    fn dispatch_record(&self, record: Vec<u8>) {
        let num_workers = self.worker_senders.len();
        let idx = (self.next_worker.fetch_add(1, Ordering::Relaxed) as usize) % num_workers;

        // Try non-blocking send first; if full, record backpressure and block
        match self.worker_senders[idx].try_send(record) {
            Ok(_) => {}
            Err(crossbeam_channel::TrySendError::Full(rec)) => {
                self.metrics
                    .total_backpressure_events
                    .fetch_add(1, Ordering::Relaxed);
                let _ = self.worker_senders[idx].send(rec);
            }
            Err(crossbeam_channel::TrySendError::Disconnected(_)) => {}
        }
    }

    pub fn get_metrics(&self) -> (u64, u64, u64, u64) {
        (
            self.metrics.total_batches_ingested.load(Ordering::Relaxed),
            self.metrics.total_records_ingested.load(Ordering::Relaxed),
            self.metrics.total_bytes_ingested.load(Ordering::Relaxed),
            self.metrics.total_backpressure_events.load(Ordering::Relaxed),
        )
    }

    pub fn shutdown(mut self) {
        self.is_running.store(false, Ordering::Release);
        for sender in self.worker_senders.drain(..) {
            drop(sender);
        }
        for handle in self.worker_handles.drain(..) {
            let _ = handle.join();
        }
    }
}
