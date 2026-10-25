/// Feature 71 – Multi-Dimensional Alert Grouping & Windowed Aggregation
///
/// Groups incoming `NormalizedAlert` objects by a composite grouping key
/// (tenant_id × entity_id × attack_technique) within tumbling or inactivity-
/// based time windows. Flushes completed incident groups to a callback when
/// the group window expires or inactivity timeout elapses.
///
/// KPI: Reduces alert volume by ≥ 80%; rolling/tumbling window support.

use crate::alert_normalizer::{AlertStatus, NormalizedAlert};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Alert Group (Incident)
// ---------------------------------------------------------------------------

/// A grouped alert incident aggregating multiple individual alerts that share
/// the same composite grouping key within a time window.
#[derive(Debug, Clone)]
pub struct AlertGroup {
    /// Unique group UUID.
    pub group_id: Uuid,
    /// Composite grouping key string.
    pub key: String,
    /// Ordered list of member alert UUIDs (not the full alert – avoids clone cost).
    pub alert_ids: Vec<Uuid>,
    /// Full copy of the seed (first) alert for incident summary.
    pub seed_alert: NormalizedAlert,
    /// Timestamp of the first alert in this group (ns).
    pub first_seen_ns: i64,
    /// Timestamp of the most recently added alert (ns).
    pub last_seen_ns: i64,
    /// Aggregated risk score: running maximum across member alerts.
    pub aggregated_risk: u8,
    /// Number of alerts aggregated (including the seed).
    pub occurrence_count: u32,
}

impl AlertGroup {
    /// Adds a new alert to this group, updating aggregate metrics.
    pub fn add_alert(&mut self, alert: &NormalizedAlert) {
        self.alert_ids.push(alert.alert_id);
        self.last_seen_ns = alert.created_time_ns;
        if alert.risk_score > self.aggregated_risk {
            self.aggregated_risk = alert.risk_score;
        }
        self.occurrence_count += 1;
    }
}

// ---------------------------------------------------------------------------
// Grouping Key Extractor
// ---------------------------------------------------------------------------

/// Extracts a composite grouping key from a `NormalizedAlert`.
///
/// Default key: `"{tenant_id}|{entity_id}|{primary_technique}"`.
/// The primary technique is the first ATT&CK tag (prefix `T`) if present,
/// otherwise the rule_id.
fn build_grouping_key(alert: &NormalizedAlert) -> String {
    let technique = alert
        .tags
        .iter()
        .find(|t| t.starts_with('T') && t.len() >= 5)
        .map(|s| s.as_str())
        .unwrap_or_else(|| alert.rule_id.as_str());

    format!("{}|{}|{}", alert.tenant_id, alert.device.hostname, technique)
}

// ---------------------------------------------------------------------------
// Alert Grouping Manager
// ---------------------------------------------------------------------------

/// Manages multi-dimensional windowed aggregation of `NormalizedAlert` objects
/// into `AlertGroup` incidents.
///
/// # Window Semantics
/// * **Group window duration**: maximum total lifespan of a group from
///   `first_seen_ns` to when it is flushed [tumbling semantics].
/// * **Inactivity timeout**: if no new alert arrives for a group within this
///   duration, the group is flushed immediately [session semantics].
///
/// `flush_if_expired` must be called periodically (e.g., from a background
/// thread) to evict idle / elapsed groups.
pub struct AlertGroupingManager {
    /// Maximum total group lifespan in nanoseconds.
    group_window_duration_ns: i64,
    /// Inactivity timeout in nanoseconds.
    inactivity_timeout_ns: i64,
    /// Active groups indexed by composite key.
    groups: Mutex<HashMap<String, AlertGroup>>,
    /// Running counter of total alerts ingested.
    total_ingested: std::sync::atomic::AtomicU64,
    /// Running counter of total groups flushed.
    total_flushed: std::sync::atomic::AtomicU64,
}

impl AlertGroupingManager {
    /// Creates a new grouping manager.
    ///
    /// # Arguments
    /// * `group_window_duration_ns` – Maximum tumbling window duration (ns).
    /// * `inactivity_timeout_ns` – Session inactivity timeout (ns).
    pub fn new(group_window_duration_ns: i64, inactivity_timeout_ns: i64) -> Self {
        Self {
            group_window_duration_ns,
            inactivity_timeout_ns,
            groups: Mutex::new(HashMap::new()),
            total_ingested: std::sync::atomic::AtomicU64::new(0),
            total_flushed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Ingests an alert into the appropriate group, creating a new group if
    /// none exists for the alert's composite key.
    ///
    /// The `emit_group_fn` callback is invoked immediately when an existing
    /// group is flushed due to tumbling-window expiry during ingestion.
    ///
    /// The alert's `status` is set to `AlertStatus::Grouped` and its
    /// `group_id` is populated.
    pub fn ingest_alert<F>(&self, alert: &mut NormalizedAlert, emit_group_fn: &mut F)
    where
        F: FnMut(AlertGroup),
    {
        self.total_ingested.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let key = build_grouping_key(alert);
        let now_ns = alert.created_time_ns;

        let mut groups = self.groups.lock();

        // Check if an existing group is still within its tumbling window.
        if let Some(existing) = groups.get_mut(&key) {
            let window_expired = now_ns - existing.first_seen_ns >= self.group_window_duration_ns;
            if !window_expired {
                // Still within window: add to existing group.
                existing.add_alert(alert);
                alert.status = AlertStatus::Grouped;
                alert.group_id = Some(existing.group_id);
                return;
            }
            // Window expired: flush the old group and create a fresh one.
            let old_group = groups.remove(&key).unwrap();
            self.total_flushed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            emit_group_fn(old_group);
        }

        // Create a new group seeded by this alert.
        let group_id = Uuid::new_v4();
        let new_group = AlertGroup {
            group_id,
            key: key.clone(),
            alert_ids: vec![alert.alert_id],
            seed_alert: alert.clone(),
            first_seen_ns: now_ns,
            last_seen_ns: now_ns,
            aggregated_risk: alert.risk_score,
            occurrence_count: 1,
        };

        alert.status = AlertStatus::Grouped;
        alert.group_id = Some(group_id);
        groups.insert(key, new_group);
    }

    /// Flushes all groups that have either exceeded the tumbling window or
    /// whose inactivity timeout has elapsed since `now_ns`.
    ///
    /// The `emit_group_fn` callback is invoked once per flushed group.
    pub fn flush_if_expired<F>(&self, now_ns: i64, emit_group_fn: &mut F)
    where
        F: FnMut(AlertGroup),
    {
        let mut groups = self.groups.lock();
        let mut to_flush = Vec::new();

        for (key, group) in groups.iter() {
            let window_expired = now_ns - group.first_seen_ns >= self.group_window_duration_ns;
            let idle_expired  = now_ns - group.last_seen_ns  >= self.inactivity_timeout_ns;
            if window_expired || idle_expired {
                to_flush.push(key.clone());
            }
        }

        for key in to_flush {
            if let Some(group) = groups.remove(&key) {
                self.total_flushed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                emit_group_fn(group);
            }
        }
    }

    /// Forces an immediate flush of ALL active groups regardless of window state.
    ///
    /// Useful for clean shutdown or test tear-down.
    pub fn flush_all<F>(&self, emit_group_fn: &mut F)
    where
        F: FnMut(AlertGroup),
    {
        let mut groups = self.groups.lock();
        for (_key, group) in groups.drain() {
            self.total_flushed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            emit_group_fn(group);
        }
    }

    /// Returns the number of active (not-yet-flushed) groups.
    pub fn active_group_count(&self) -> usize {
        self.groups.lock().len()
    }

    /// Returns (total_ingested, total_flushed) counters.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.total_ingested.load(std::sync::atomic::Ordering::Relaxed),
            self.total_flushed.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}
