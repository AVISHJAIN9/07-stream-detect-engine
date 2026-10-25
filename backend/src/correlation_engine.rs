/// Feature 72 – Deterministic Cross-Alert Correlation ID Graph Linking
///
/// Generates deterministic correlation IDs that link distinct alerts belonging
/// to the same multi-stage intrusion campaign or lateral movement sequence.
///
/// Algorithm:
///   CorrelationID = Hash64(tenant_id ‖ root_entity ‖ temporal_epoch_bucket)
///
/// The temporal epoch bucket quantises wall-clock time into fixed-width slots
/// (default 10 minutes = 600_000_000_000 ns) so that alerts on the same
/// entity within the same bucket receive the same correlation token.
///
/// A Union-Find (Disjoint-Set) graph additionally merges buckets when two
/// entities are observed communicating within the same epoch, propagating the
/// same correlation ID across both.
///
/// KPI: Correlation token generation latency ≤ 40 ns.

use crate::alert_normalizer::NormalizedAlert;
use crate::dedup_key_generator::Murmur3Hasher64;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Temporal Epoch Bucket
// ---------------------------------------------------------------------------

/// Quantises a nanosecond timestamp into a fixed-width epoch bucket index.
///
/// Default bucket width: 600,000,000,000 ns (10 minutes).
#[inline]
fn epoch_bucket(timestamp_ns: i64, bucket_width_ns: i64) -> i64 {
    // Saturating division for negative timestamps (pre-epoch edge case).
    if bucket_width_ns == 0 {
        return 0;
    }
    timestamp_ns.div_euclid(bucket_width_ns)
}

// ---------------------------------------------------------------------------
// Correlation ID computation
// ---------------------------------------------------------------------------

/// Computes a deterministic 64-bit correlation token.
///
/// Inputs:
/// * `tenant_id` – Multi-tenant isolation prefix.
/// * `root_entity` – Primary entity ID (hostname, user, IP).
/// * `epoch_bucket` – Temporal epoch bucket index.
#[inline]
pub fn compute_correlation_id(tenant_id: &str, root_entity: &str, epoch: i64) -> u64 {
    let mut h = Murmur3Hasher64::new(0xC0FFEE_DEAD_BEEF_CAFEu64);
    h.write_str(tenant_id);
    h.write_str("\x00");
    h.write_str(root_entity);
    h.write_str("\x00");
    // Write epoch as little-endian bytes for endian-stable hash input.
    h.write_bytes(&epoch.to_le_bytes());
    h.finish()
}

// ---------------------------------------------------------------------------
// Entity Graph Node (Union-Find)
// ---------------------------------------------------------------------------

/// A node in the entity correlation graph.
struct GraphNode {
    /// Canonical entity identifier.
    entity: String,
    /// Union-Find parent pointer (self-ref = root).
    parent: String,
    /// Union-Find rank for path compression.
    rank: u32,
    /// Assigned correlation ID for this component.
    correlation_id: u64,
    /// Timestamp of most recent activity in this node's component.
    last_seen_ns: i64,
}

// ---------------------------------------------------------------------------
// Correlation Engine
// ---------------------------------------------------------------------------

/// Maintains a temporal entity-graph that tracks relationships between entities
/// (host→host lateral movement, user→host login) and assigns shared correlation
/// IDs to alerts belonging to the same inferred campaign.
///
/// # Architecture
/// * A Union-Find graph tracks which entities belong to the same campaign.
/// * On each alert ingestion, the primary entity is looked up or inserted.
/// * If the alert's network destination entity is known, the two entities are
///   merged into a single component and share one correlation ID.
/// * Components are evicted when their last-activity falls outside the temporal
///   window.
pub struct CorrelationEngine {
    /// Width of a temporal epoch bucket in nanoseconds.
    bucket_width_ns: i64,
    /// Union-Find graph protected by a single mutex.
    /// Lock contention is acceptable for monitoring paths; alert ingestion is
    /// the hot path and must remain fast.
    graph: Mutex<CorrelationGraph>,
    /// Total correlation IDs assigned.
    total_assigned: AtomicU64,
    /// Total component merges performed.
    total_merges: AtomicU64,
}

/// Internal Union-Find correlation graph.
struct CorrelationGraph {
    nodes: HashMap<String, GraphNode>,
}

impl CorrelationGraph {
    fn new() -> Self {
        Self { nodes: HashMap::new() }
    }

    /// Finds the root of the component containing `entity`, performing path
    /// compression along the way.
    fn find_root(&mut self, entity: &str) -> String {
        // Iterative path compression.
        let mut current = entity.to_string();
        loop {
            let parent = self.nodes.get(&current).map(|n| n.parent.clone());
            match parent {
                None => break current,
                Some(p) if p == current => break current,
                Some(p) => {
                    // Grab the grandparent for compression.
                    let grandparent = self.nodes.get(&p).map(|n| n.parent.clone());
                    if let Some(gp) = grandparent {
                        if gp != p {
                            if let Some(node) = self.nodes.get_mut(&current) {
                                node.parent = gp;
                            }
                        }
                    }
                    current = p;
                }
            }
        }
    }

    /// Inserts an entity node if it does not already exist.
    /// Returns the correlation ID assigned to this entity's component.
    fn get_or_insert(&mut self, entity: &str, tenant_id: &str, now_ns: i64, bucket_width_ns: i64) -> u64 {
        if !self.nodes.contains_key(entity) {
            let bucket = epoch_bucket(now_ns, bucket_width_ns);
            let cid = compute_correlation_id(tenant_id, entity, bucket);
            self.nodes.insert(entity.to_string(), GraphNode {
                entity: entity.to_string(),
                parent: entity.to_string(),
                rank: 0,
                correlation_id: cid,
                last_seen_ns: now_ns,
            });
            cid
        } else {
            let root = self.find_root(entity);
            let cid = self.nodes.get(&root).map(|n| n.correlation_id).unwrap_or(0);
            if let Some(node) = self.nodes.get_mut(entity) {
                node.last_seen_ns = now_ns;
            }
            cid
        }
    }

    /// Union-Find merge: merges the components of `a` and `b` under the lower
    /// correlation ID.  Returns the shared correlation ID.
    fn union(&mut self, a: &str, b: &str, tenant_id: &str, now_ns: i64, bucket_width_ns: i64) -> u64 {
        // Ensure both nodes exist.
        self.get_or_insert(a, tenant_id, now_ns, bucket_width_ns);
        self.get_or_insert(b, tenant_id, now_ns, bucket_width_ns);

        let root_a = self.find_root(a);
        let root_b = self.find_root(b);

        if root_a == root_b {
            // Already in same component.
            return self.nodes.get(&root_a).map(|n| n.correlation_id).unwrap_or(0);
        }

        let (rank_a, cid_a) = self.nodes.get(&root_a)
            .map(|n| (n.rank, n.correlation_id))
            .unwrap_or((0, 0));
        let (rank_b, cid_b) = self.nodes.get(&root_b)
            .map(|n| (n.rank, n.correlation_id))
            .unwrap_or((0, 0));

        // Merge smaller rank under larger; use lexicographically smaller CID.
        let shared_cid = cid_a.min(cid_b);

        if rank_a >= rank_b {
            // root_b merges under root_a
            if let Some(n) = self.nodes.get_mut(&root_b) { n.parent = root_a.clone(); }
            if let Some(n) = self.nodes.get_mut(&root_a) {
                if rank_a == rank_b { n.rank += 1; }
                n.correlation_id = shared_cid;
            }
        } else {
            // root_a merges under root_b
            if let Some(n) = self.nodes.get_mut(&root_a) { n.parent = root_b.clone(); }
            if let Some(n) = self.nodes.get_mut(&root_b) {
                n.correlation_id = shared_cid;
            }
        }

        shared_cid
    }

    /// Evicts nodes whose last activity is older than `window_ns` before `now_ns`.
    fn evict_stale(&mut self, now_ns: i64, window_ns: i64) -> usize {
        let cutoff = now_ns - window_ns;
        let before = self.nodes.len();
        self.nodes.retain(|_, node| node.last_seen_ns >= cutoff);
        before - self.nodes.len()
    }
}

impl CorrelationEngine {
    /// Creates a new `CorrelationEngine`.
    ///
    /// # Arguments
    /// * `bucket_width_ns` – Temporal epoch bucket width in nanoseconds.
    ///   Alerts on the same entity within the same bucket share a correlation ID.
    ///   Default: 600,000,000,000 ns (10 minutes).
    pub fn new(bucket_width_ns: i64) -> Self {
        Self {
            bucket_width_ns,
            graph: Mutex::new(CorrelationGraph::new()),
            total_assigned: AtomicU64::new(0),
            total_merges: AtomicU64::new(0),
        }
    }

    /// Creates an engine with the default 10-minute bucket width.
    pub fn default_10min() -> Self {
        Self::new(600_000_000_000i64)
    }

    /// Assigns a correlation ID to a `NormalizedAlert`.
    ///
    /// # Behavior
    /// 1. The alert's primary entity (`device.hostname`) is resolved against
    ///    the temporal graph.
    /// 2. If the alert carries a network destination entity (`network.dst_ip`),
    ///    the two entities are merged, sharing a single correlation token.
    /// 3. The resolved correlation ID is written to `alert.correlation_id`.
    ///
    /// # Returns
    /// The 64-bit deterministic correlation token.
    pub fn assign_correlation_id(&self, alert: &mut NormalizedAlert) -> u64 {
        let primary_entity = alert.device.hostname.clone();
        let dst_entity = alert.network.dst_ip.clone();
        let tenant_id = alert.tenant_id.clone();
        let now_ns = alert.created_time_ns;

        let mut graph = self.graph.lock();

        let cid = if let Some(dst) = dst_entity {
            // Merge src and dst entities into the same campaign component.
            let cid = graph.union(&primary_entity, &dst, &tenant_id, now_ns, self.bucket_width_ns);
            self.total_merges.fetch_add(1, Ordering::Relaxed);
            cid
        } else {
            graph.get_or_insert(&primary_entity, &tenant_id, now_ns, self.bucket_width_ns)
        };

        alert.correlation_id = Some(cid);
        self.total_assigned.fetch_add(1, Ordering::Relaxed);
        cid
    }

    /// Computes a deterministic correlation ID for an (entity, timestamp) pair
    /// without modifying the alert.  Useful for test assertions.
    pub fn compute_deterministic(&self, tenant_id: &str, entity: &str, timestamp_ns: i64) -> u64 {
        let bucket = epoch_bucket(timestamp_ns, self.bucket_width_ns);
        compute_correlation_id(tenant_id, entity, bucket)
    }

    /// Evicts stale graph nodes older than `max_age_ns` before `now_ns`.
    pub fn evict_stale(&self, now_ns: i64, max_age_ns: i64) -> usize {
        self.graph.lock().evict_stale(now_ns, max_age_ns)
    }

    /// Returns (total_assigned, total_merges) counters.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.total_assigned.load(Ordering::Relaxed),
            self.total_merges.load(Ordering::Relaxed),
        )
    }
}
