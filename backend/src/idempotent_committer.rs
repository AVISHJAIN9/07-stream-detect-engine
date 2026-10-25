use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Partition identifier
// ---------------------------------------------------------------------------

/// Identifies a Kafka/Redpanda topic-partition stream uniquely.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PartitionId {
    pub topic: String,
    pub partition: i32,
}

impl PartitionId {
    pub fn new(topic: impl Into<String>, partition: i32) -> Self {
        Self { topic: topic.into(), partition }
    }
}

// ---------------------------------------------------------------------------
// Commit result
// ---------------------------------------------------------------------------

/// Outcome of a single `try_commit` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitResult {
    /// Mutation was applied and the watermark was advanced to `offset`.
    Applied { partition: PartitionId, offset: u64 },
    /// The offset had already been applied; mutation was discarded as an
    /// idempotent no-op to prevent double-counting.
    DuplicateIgnored { partition: PartitionId, offset: u64, last_applied: u64 },
}

impl CommitResult {
    /// Returns `true` if the mutation was actually applied.
    #[inline]
    pub fn was_applied(&self) -> bool {
        matches!(self, CommitResult::Applied { .. })
    }
}

// ---------------------------------------------------------------------------
// Per-partition watermark record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PartitionState {
    /// The highest stream offset whose mutation has been durably applied.
    last_applied_offset: u64,
    /// Running count of mutations applied (forward progress).
    applied_count: u64,
    /// Running count of duplicate / replay detections.
    duplicate_count: u64,
}

impl PartitionState {
    fn new() -> Self {
        Self {
            last_applied_offset: u64::MAX, // sentinel: nothing applied yet
            applied_count: 0,
            duplicate_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Idempotent State Commit Barrier
// ---------------------------------------------------------------------------

/// Epoch-synchronized, exactly-once-oriented state transition commit barrier.
///
/// # Semantics
/// * Each partition maintains a monotonically increasing `last_applied_offset`.
/// * When `try_commit(partition, offset, mutation_fn)` is called:
///   - If `offset <= last_applied_offset` → the event is a Kafka consumer
///     replay or a duplicate delivery; the mutation function is *not* called
///     and `CommitResult::DuplicateIgnored` is returned.
///   - If `offset > last_applied_offset` → the mutation is applied and
///     `last_applied_offset` is advanced atomically under the partition's lock.
///
/// # Exactly-once guarantee scope
/// The barrier provides idempotent *application-level* exactly-once semantics.
/// It does **not** coordinate with an external transaction log; it is the
/// application-side guard that pairs with a Kafka idempotent producer +
/// committed-offset watermark to achieve end-to-end exactly-once delivery.
///
/// # Concurrency model
/// * Per-partition `RwLock`-guarded records prevent any cross-partition false
///   sharing.
/// * Global counters are updated with `Relaxed` ordering (telemetry only).
pub struct IdempotentStateBarrier {
    /// Guarded map of per-partition watermarks.
    partitions: RwLock<HashMap<PartitionId, parking_lot::Mutex<PartitionState>>>,
    // Global telemetry
    total_commits_applied: AtomicU64,
    total_duplicates_ignored: AtomicU64,
    total_partitions_registered: AtomicU64,
}

impl IdempotentStateBarrier {
    pub fn new() -> Self {
        Self {
            partitions: RwLock::new(HashMap::with_capacity(64)),
            total_commits_applied: AtomicU64::new(0),
            total_duplicates_ignored: AtomicU64::new(0),
            total_partitions_registered: AtomicU64::new(0),
        }
    }

    // ------------------------------------------------------------------
    // Partition registration
    // ------------------------------------------------------------------

    /// Explicitly pre-registers a partition with a known recovery offset.
    ///
    /// Useful during consumer startup when the committed offset has been
    /// restored from a checkpoint: any events with `offset <= recovery_offset`
    /// are treated as replayed and silently skipped.
    pub fn register_partition(&self, partition: PartitionId, recovery_offset: u64) {
        let mut map = self.partitions.write();
        map.entry(partition).or_insert_with(|| {
            self.total_partitions_registered.fetch_add(1, Ordering::Relaxed);
            let mut state = PartitionState::new();
            state.last_applied_offset = recovery_offset;
            parking_lot::Mutex::new(state)
        });
    }

    // ------------------------------------------------------------------
    // Core commit gate
    // ------------------------------------------------------------------

    /// Attempts to apply `mutation_fn` for the event at `(partition, offset)`.
    ///
    /// `mutation_fn` receives no arguments; it should close over whatever state
    /// it needs to mutate.  It will be called at most once per unique offset.
    ///
    /// # Returns
    /// * `CommitResult::Applied` if the mutation was executed.
    /// * `CommitResult::DuplicateIgnored` if the offset is a replay.
    pub fn try_commit<F>(&self, partition: PartitionId, offset: u64, mutation_fn: F) -> CommitResult
    where
        F: FnOnce(),
    {
        // --- Ensure partition record exists (lazy registration) ---
        {
            let read_guard = self.partitions.read();
            if read_guard.contains_key(&partition) {
                let state_mutex = read_guard.get(&partition).unwrap();
                let mut state = state_mutex.lock();

                // Case A: fresh partition (sentinel u64::MAX)
                if state.last_applied_offset == u64::MAX || offset > state.last_applied_offset {
                    mutation_fn();
                    state.last_applied_offset = offset;
                    state.applied_count += 1;
                    self.total_commits_applied.fetch_add(1, Ordering::Relaxed);
                    return CommitResult::Applied {
                        partition,
                        offset,
                    };
                }

                // Case B: duplicate / replay
                let last = state.last_applied_offset;
                state.duplicate_count += 1;
                self.total_duplicates_ignored.fetch_add(1, Ordering::Relaxed);
                return CommitResult::DuplicateIgnored {
                    partition,
                    offset,
                    last_applied: last,
                };
            }
        }

        // Partition not yet registered → create under write lock
        {
            let mut write_guard = self.partitions.write();
            // Double-checked locking: another thread may have inserted while we
            // were waiting for the write lock.
            if !write_guard.contains_key(&partition) {
                let mut state = PartitionState::new();
                state.last_applied_offset = offset;
                state.applied_count = 1;
                mutation_fn();
                write_guard.insert(partition.clone(), parking_lot::Mutex::new(state));
                self.total_partitions_registered.fetch_add(1, Ordering::Relaxed);
                self.total_commits_applied.fetch_add(1, Ordering::Relaxed);
                return CommitResult::Applied { partition, offset };
            }
        }

        // Race resolved: fall through to normal read path by recursing once.
        // This branch is taken at most once per partition in the rare race.
        self.try_commit(partition, offset, mutation_fn)
    }

    // ------------------------------------------------------------------
    // Inspection helpers
    // ------------------------------------------------------------------

    /// Returns the `last_applied_offset` for a partition, or `None` if the
    /// partition has not yet been registered.
    pub fn last_applied_offset(&self, partition: &PartitionId) -> Option<u64> {
        let map = self.partitions.read();
        map.get(partition).map(|s| s.lock().last_applied_offset)
    }

    /// Telemetry snapshot.
    pub fn stats(&self) -> BarrierStats {
        BarrierStats {
            total_commits_applied: self.total_commits_applied.load(Ordering::Relaxed),
            total_duplicates_ignored: self.total_duplicates_ignored.load(Ordering::Relaxed),
            registered_partitions: self.partitions.read().len(),
        }
    }
}

impl Default for IdempotentStateBarrier {
    fn default() -> Self {
        Self::new()
    }
}

/// Telemetry snapshot for `IdempotentStateBarrier`.
#[derive(Debug, Clone, PartialEq)]
pub struct BarrierStats {
    pub total_commits_applied: u64,
    pub total_duplicates_ignored: u64,
    pub registered_partitions: usize,
}
