use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Shard-level atomic metrics record
// ---------------------------------------------------------------------------

/// All metrics for a single shard, held in a cache-line-friendly aligned
/// struct.  Each field is an independent `AtomicU64` updated with `Relaxed`
/// ordering (observation latency is acceptable; what matters is that no
/// counter ever loses an increment).
#[repr(align(64))]
pub struct ShardMetrics {
    /// Count of state keys currently resident in this shard.
    pub active_keys: AtomicU64,
    /// Approximate heap bytes allocated for keys + values in this shard.
    pub allocated_bytes: AtomicU64,
    /// Number of keys evicted due to TTL expiry.
    pub ttl_evictions: AtomicU64,
    /// Number of keys evicted due to LRU / memory-pressure shedding.
    pub lru_evictions: AtomicU64,
    /// Successful state reads (key found).
    pub hits: AtomicU64,
    /// Failed state reads (key absent).
    pub misses: AtomicU64,
    /// Number of state writes applied.
    pub writes: AtomicU64,
}

impl ShardMetrics {
    pub const fn new() -> Self {
        Self {
            active_keys: AtomicU64::new(0),
            allocated_bytes: AtomicU64::new(0),
            ttl_evictions: AtomicU64::new(0),
            lru_evictions: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            writes: AtomicU64::new(0),
        }
    }

    // ------------------------------------------------------------------
    // Increment helpers – all Relaxed (telemetry path)
    // ------------------------------------------------------------------

    #[inline]
    pub fn inc_active_keys(&self) {
        self.active_keys.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn dec_active_keys(&self) {
        self.active_keys.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_allocated(&self, bytes: u64) {
        self.allocated_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn sub_allocated(&self, bytes: u64) {
        self.allocated_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_ttl_evictions(&self) {
        self.ttl_evictions.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_lru_evictions(&self) {
        self.lru_evictions.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_hits(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_misses(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_writes(&self) {
        self.writes.fetch_add(1, Ordering::Relaxed);
    }

    /// Read a consistent snapshot without any cross-field atomicity guarantee
    /// (sufficient for monitoring dashboards where a per-field Relaxed read is
    /// acceptable).
    pub fn snapshot(&self) -> ShardMetricSnapshot {
        ShardMetricSnapshot {
            active_keys: self.active_keys.load(Ordering::Relaxed),
            allocated_bytes: self.allocated_bytes.load(Ordering::Relaxed),
            ttl_evictions: self.ttl_evictions.load(Ordering::Relaxed),
            lru_evictions: self.lru_evictions.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
        }
    }
}

impl Default for ShardMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Plain-data snapshot of a single shard's metrics.
#[derive(Debug, Clone, PartialEq)]
pub struct ShardMetricSnapshot {
    pub active_keys: u64,
    pub allocated_bytes: u64,
    pub ttl_evictions: u64,
    pub lru_evictions: u64,
    pub hits: u64,
    pub misses: u64,
    pub writes: u64,
}

impl ShardMetricSnapshot {
    /// Accumulates another snapshot into this one (used for aggregation).
    pub fn merge(&mut self, other: &ShardMetricSnapshot) {
        self.active_keys += other.active_keys;
        self.allocated_bytes += other.allocated_bytes;
        self.ttl_evictions += other.ttl_evictions;
        self.lru_evictions += other.lru_evictions;
        self.hits += other.hits;
        self.misses += other.misses;
        self.writes += other.writes;
    }
}

// ---------------------------------------------------------------------------
// Global metrics aggregator registry
// ---------------------------------------------------------------------------

/// Lock-free, sharded state telemetry registry.
///
/// # Design
/// * One `ShardMetrics` per store shard, each 64-byte cache-line aligned.
/// * All updates are performed via `fetch_add` / `fetch_sub` with `Relaxed`
///   ordering – no cross-thread ordering guarantees are needed for counters.
/// * `aggregate()` scans all shards with `Relaxed` loads and returns a single
///   `ShardMetricSnapshot` that represents a best-effort consistent view
///   (suitable for Prometheus scrapes where the monitoring interval >> update
///   frequency).
/// * `format_prometheus()` emits the standard OpenMetrics text exposition.
pub struct StateMetricsRegistry {
    shards: Vec<ShardMetrics>,
    num_shards: usize,
}

impl StateMetricsRegistry {
    /// Creates a registry with `num_shards` independent metric shards.
    pub fn new(num_shards: usize) -> Self {
        assert!(num_shards > 0 && num_shards.is_power_of_two(),
            "num_shards must be a positive power of two");
        let mut shards = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            shards.push(ShardMetrics::new());
        }
        Self { shards, num_shards }
    }

    /// Returns a reference to the shard for a given shard index.
    #[inline]
    pub fn shard(&self, shard_idx: usize) -> &ShardMetrics {
        debug_assert!(shard_idx < self.num_shards);
        &self.shards[shard_idx]
    }

    /// Aggregates all shard metrics into a single consolidated snapshot.
    pub fn aggregate(&self) -> ShardMetricSnapshot {
        let mut total = ShardMetricSnapshot {
            active_keys: 0,
            allocated_bytes: 0,
            ttl_evictions: 0,
            lru_evictions: 0,
            hits: 0,
            misses: 0,
            writes: 0,
        };
        for shard in &self.shards {
            total.merge(&shard.snapshot());
        }
        total
    }

    /// Formats the aggregate metrics in standard Prometheus / OpenMetrics text
    /// exposition format (version 0.0.4 compatible).
    pub fn format_prometheus(&self) -> String {
        let agg = self.aggregate();
        let hit_ratio: f64 = if agg.hits + agg.misses > 0 {
            agg.hits as f64 / (agg.hits + agg.misses) as f64
        } else {
            0.0
        };

        format!(
            concat!(
                "# HELP sde_state_active_keys Number of keys currently resident in the keyed state store\n",
                "# TYPE sde_state_active_keys gauge\n",
                "sde_state_active_keys {active_keys}\n",
                "# HELP sde_state_allocated_bytes Approximate heap bytes allocated for state keys and values\n",
                "# TYPE sde_state_allocated_bytes gauge\n",
                "sde_state_allocated_bytes {allocated_bytes}\n",
                "# HELP sde_state_ttl_evictions_total Total number of keys evicted due to TTL expiry\n",
                "# TYPE sde_state_ttl_evictions_total counter\n",
                "sde_state_ttl_evictions_total {ttl_evictions}\n",
                "# HELP sde_state_lru_evictions_total Total number of keys evicted by LRU pressure shedding\n",
                "# TYPE sde_state_lru_evictions_total counter\n",
                "sde_state_lru_evictions_total {lru_evictions}\n",
                "# HELP sde_state_read_hits_total Total successful state key lookups\n",
                "# TYPE sde_state_read_hits_total counter\n",
                "sde_state_read_hits_total {hits}\n",
                "# HELP sde_state_read_misses_total Total failed state key lookups\n",
                "# TYPE sde_state_read_misses_total counter\n",
                "sde_state_read_misses_total {misses}\n",
                "# HELP sde_state_writes_total Total state write operations applied\n",
                "# TYPE sde_state_writes_total counter\n",
                "sde_state_writes_total {writes}\n",
                "# HELP sde_state_cache_hit_ratio Ratio of hits to total reads (gauge)\n",
                "# TYPE sde_state_cache_hit_ratio gauge\n",
                "sde_state_cache_hit_ratio {hit_ratio:.6}\n",
                "# HELP sde_state_num_shards Number of metric shards in the registry\n",
                "# TYPE sde_state_num_shards gauge\n",
                "sde_state_num_shards {num_shards}\n",
            ),
            active_keys = agg.active_keys,
            allocated_bytes = agg.allocated_bytes,
            ttl_evictions = agg.ttl_evictions,
            lru_evictions = agg.lru_evictions,
            hits = agg.hits,
            misses = agg.misses,
            writes = agg.writes,
            hit_ratio = hit_ratio,
            num_shards = self.num_shards,
        )
    }

    /// Number of shards in this registry.
    #[inline]
    pub fn num_shards(&self) -> usize {
        self.num_shards
    }
}
