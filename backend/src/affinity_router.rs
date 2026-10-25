use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use crossbeam_channel::{bounded, Receiver, Sender};
use crate::canonical_normalizer::CanonicalEvent;

/// Jump Consistent Hash algorithm (Lamping & Veach, Google 2014)
/// Maps a 64-bit key uniformly to one of `num_buckets` with minimal remapping on bucket change
#[inline(always)]
pub fn jump_consistent_hash(mut key: u64, num_buckets: usize) -> usize {
    let mut b: i64 = -1;
    let mut j: i64 = 0;
    let num_b = num_buckets as i64;

    while j < num_b {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        let rand_val = ((key >> 33).wrapping_add(1)) as f64 / (1u64 << 31) as f64;
        j = ((b + 1) as f64 / rand_val).floor() as i64;
    }
    b as usize
}

/// Fast MurmurHash3 64-bit string hasher for routing key calculation
#[inline(always)]
pub fn hash_routing_key(key: &str) -> u64 {
    let bytes = key.as_bytes();
    let mut h: u64 = 0x5f3759df;
    let mut cursor = 0;
    while cursor + 8 <= bytes.len() {
        let mut k = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        k = k.wrapping_mul(0xc6a4a7935bd1e995);
        k ^= k >> 47;
        k = k.wrapping_mul(0xc6a4a7935bd1e995);
        h ^= k;
        h = h.wrapping_mul(0xc6a4a7935bd1e995);
        cursor += 8;
    }
    let rem = bytes.len() - cursor;
    if rem > 0 {
        let mut tail = 0u64;
        for i in 0..rem {
            tail |= (bytes[cursor + i] as u64) << (i * 8);
        }
        h ^= tail;
        h = h.wrapping_mul(0xc6a4a7935bd1e995);
    }
    h ^= h >> 47;
    h = h.wrapping_mul(0xc6a4a7935bd1e995);
    h ^= h >> 47;
    h
}

pub struct PartitionRouter {
    num_partitions: usize,
    worker_senders: Vec<Sender<CanonicalEvent>>,
    worker_handles: Vec<JoinHandle<()>>,
    partition_counts: Vec<Arc<AtomicU64>>,
    is_running: Arc<AtomicBool>,
    total_routed: AtomicU64,
}

impl PartitionRouter {
    pub fn new(
        num_partitions: usize,
        queue_capacity: usize,
        worker_consumer: Arc<dyn Fn(usize, CanonicalEvent) + Send + Sync + 'static>,
    ) -> Self {
        let mut senders = Vec::with_capacity(num_partitions);
        let mut handles = Vec::with_capacity(num_partitions);
        let mut counts = Vec::with_capacity(num_partitions);
        let is_running = Arc::new(AtomicBool::new(true));

        for partition_id in 0..num_partitions {
            let (tx, rx): (Sender<CanonicalEvent>, Receiver<CanonicalEvent>) = bounded(queue_capacity);
            senders.push(tx);
            let counter = Arc::new(AtomicU64::new(0));
            counts.push(Arc::clone(&counter));

            let running = Arc::clone(&is_running);
            let consumer = Arc::clone(&worker_consumer);

            let handle = thread::spawn(move || {
                while running.load(Ordering::Acquire) || !rx.is_empty() {
                    match rx.recv_timeout(std::time::Duration::from_millis(20)) {
                        Ok(event) => {
                            counter.fetch_add(1, Ordering::Relaxed);
                            consumer(partition_id, event);
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    }
                }
            });

            handles.push(handle);
        }

        Self {
            num_partitions,
            worker_senders: senders,
            worker_handles: handles,
            partition_counts: counts,
            is_running,
            total_routed: AtomicU64::new(0),
        }
    }

    /// Determines target partition deterministically via Jump Consistent Hash
    #[inline(always)]
    pub fn get_target_partition(&self, routing_key: &str) -> usize {
        let key_hash = hash_routing_key(routing_key);
        jump_consistent_hash(key_hash, self.num_partitions)
    }

    /// Routes CanonicalEvent to its assigned partition worker queue with entity affinity
    pub fn route(&self, event: CanonicalEvent) -> Result<usize, String> {
        let routing_key = if !event.entity_id.is_empty() {
            &event.entity_id
        } else {
            &event.source
        };

        let partition_id = self.get_target_partition(routing_key);
        let sender = &self.worker_senders[partition_id];

        match sender.send(event) {
            Ok(_) => {
                self.total_routed.fetch_add(1, Ordering::Relaxed);
                Ok(partition_id)
            }
            Err(e) => Err(format!("Partition {} channel disconnected: {:?}", partition_id, e)),
        }
    }

    pub fn get_partition_distribution(&self) -> Vec<u64> {
        self.partition_counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect()
    }

    pub fn total_routed(&self) -> u64 {
        self.total_routed.load(Ordering::Relaxed)
    }

    pub fn shutdown(mut self) {
        self.is_running.store(false, Ordering::Release);
        for tx in self.worker_senders.drain(..) {
            drop(tx);
        }
        for handle in self.worker_handles.drain(..) {
            let _ = handle.join();
        }
    }
}
