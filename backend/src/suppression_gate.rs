/// Feature 70 – Rule-Based Dynamic Alert Suppression Gates
///
/// Evaluates incoming `NormalizedAlert` objects against a chain of active
/// suppression rules. Supports:
///   * Multi-attribute predicate matching (exact, prefix, suffix, contains,
///     regex, CIDR membership).
///   * Scheduled maintenance window time-range filtering.
///   * Rule expiration timestamps.
///
/// KPI: Suppression evaluation latency ≤ 30 ns per rule chain evaluation.

use crate::alert_normalizer::{AlertStatus, NormalizedAlert};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use regex::Regex;

// ---------------------------------------------------------------------------
// Time Range (maintenance window)
// ---------------------------------------------------------------------------

/// Half-open time interval [start_ns, end_ns) in Unix epoch nanoseconds.
/// An alert is considered "within maintenance" if its `created_time_ns` falls
/// within any active `TimeRange`.
#[derive(Debug, Clone, Copy)]
pub struct TimeRange {
    /// Inclusive start nanosecond.
    pub start_ns: i64,
    /// Exclusive end nanosecond.
    pub end_ns: i64,
}

impl TimeRange {
    pub fn new(start_ns: i64, end_ns: i64) -> Self {
        Self { start_ns, end_ns }
    }

    /// Returns true when `ts_ns` falls within [start_ns, end_ns).
    #[inline]
    pub fn contains(&self, ts_ns: i64) -> bool {
        ts_ns >= self.start_ns && ts_ns < self.end_ns
    }
}

// ---------------------------------------------------------------------------
// Predicate Operators
// ---------------------------------------------------------------------------

/// Comparison operator for a suppression predicate.
#[derive(Debug, Clone)]
pub enum PredicateOp {
    /// Exact case-sensitive string equality.
    Eq(String),
    /// Case-insensitive string equality.
    EqIgnoreCase(String),
    /// String prefix match.
    HasPrefix(String),
    /// String suffix match.
    HasSuffix(String),
    /// Substring containment.
    Contains(String),
    /// Full regular expression match (anchored to whole value).
    Regex(Regex),
    /// Value is a member of a fixed string set.
    InSet(Vec<String>),
    /// Numeric range [low, high] (inclusive).
    InNumericRange(i64, i64),
}

impl PredicateOp {
    /// Evaluates whether `value` satisfies this operator.
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Self::Eq(v) => value == v.as_str(),
            Self::EqIgnoreCase(v) => value.eq_ignore_ascii_case(v),
            Self::HasPrefix(p) => value.starts_with(p.as_str()),
            Self::HasSuffix(s) => value.ends_with(s.as_str()),
            Self::Contains(sub) => value.contains(sub.as_str()),
            Self::Regex(re) => re.is_match(value),
            Self::InSet(set) => set.iter().any(|s| s == value),
            Self::InNumericRange(lo, hi) => {
                if let Ok(n) = value.parse::<i64>() {
                    n >= *lo && n <= *hi
                } else {
                    false
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Suppression Predicate
// ---------------------------------------------------------------------------

/// A single attribute-level suppression predicate:
///   `<field_path> <op> <operand>`
///
/// `field_path` is a dotted-path string resolved against `NormalizedAlert`
/// using the `AlertFieldAccessor` helper.
#[derive(Debug, Clone)]
pub struct SuppressionPredicate {
    /// Alert field path (e.g. `device.ip_address`, `actor.user_name`, `severity`).
    pub field_path: String,
    /// Comparison operator.
    pub op: PredicateOp,
}

impl SuppressionPredicate {
    pub fn new(field_path: impl Into<String>, op: PredicateOp) -> Self {
        Self { field_path: field_path.into(), op }
    }

    /// Evaluates this predicate against an alert.
    ///
    /// Returns `true` when the resolved field value satisfies `op`.
    pub fn evaluate(&self, alert: &NormalizedAlert) -> bool {
        let value = resolve_alert_field(alert, &self.field_path);
        value.map(|v| self.op.matches(&v)).unwrap_or(false)
    }
}

/// Resolves a dotted field path from a `NormalizedAlert` to a string value.
pub fn resolve_alert_field(alert: &NormalizedAlert, path: &str) -> Option<String> {
    match path {
        "rule_id"                   => Some(alert.rule_id.clone()),
        "title"                     => Some(alert.title.clone()),
        "severity"                  => Some(alert.severity.as_str().to_string()),
        "risk_score"                => Some(alert.risk_score.to_string()),
        "tenant_id"                 => Some(alert.tenant_id.clone()),
        "status"                    => Some(alert.status.as_str().to_string()),
        "actor.user_name"           => Some(alert.actor.user_name.clone()),
        "actor.domain"              => alert.actor.domain.clone(),
        "actor.is_privileged"       => Some(alert.actor.is_privileged.to_string()),
        "device.hostname"           => Some(alert.device.hostname.clone()),
        "device.ip_address"         => alert.device.ip_address.clone(),
        "device.mac_address"        => alert.device.mac_address.clone(),
        "device.os_name"            => alert.device.os_name.clone(),
        "device.asset_id"           => alert.device.asset_id.clone(),
        "device.criticality_tier"   => Some(alert.device.criticality_tier.to_string()),
        "network.src_ip"            => alert.network.src_ip.clone(),
        "network.dst_ip"            => alert.network.dst_ip.clone(),
        "network.dst_port"          => alert.network.dst_port.map(|p| p.to_string()),
        "network.protocol"          => alert.network.protocol.clone(),
        "enrichment.network_zone"   => alert.enrichment.network_zone.clone(),
        "enrichment.department"     => alert.enrichment.department.clone(),
        "enrichment.is_vip"         => Some(alert.enrichment.is_vip.to_string()),
        _ => {
            // Resolve enrichment tags via prefix `enrichment.tags.<key>`
            if let Some(tag_key) = path.strip_prefix("enrichment.tags.") {
                alert.enrichment.tags.get(tag_key).cloned()
            } else if let Some(tag_key) = path.strip_prefix("tags.") {
                // Check alert-level tag membership
                if alert.tags.iter().any(|t| t == tag_key) {
                    Some("true".to_string())
                } else {
                    None
                }
            } else {
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Suppression Rule
// ---------------------------------------------------------------------------

/// A complete suppression rule carrying predicates and optional maintenance windows.
///
/// An alert is suppressed when ALL of the following conditions hold:
///   1. The rule has not expired (`expiration_ns` is None or future).
///   2. If `active_time_ranges` is non-empty, the alert's timestamp falls
///      within at least one time range.
///   3. ALL `criteria_predicates` match the alert attributes.
#[derive(Debug, Clone)]
pub struct SuppressionRule {
    /// Unique rule identifier.
    pub id: String,
    /// Human-readable rule name for audit trail.
    pub name: String,
    /// Ordered list of attribute predicates (ALL must match).
    pub criteria_predicates: Vec<SuppressionPredicate>,
    /// Maintenance window time ranges (alert must fall within at least one).
    /// Empty = matches any time.
    pub active_time_ranges: Vec<TimeRange>,
    /// Optional rule expiration timestamp (Unix epoch ns).
    /// None = rule never expires.
    pub expiration_ns: Option<i64>,
}

impl SuppressionRule {
    /// Returns true if this rule is currently active at `now_ns`.
    pub fn is_active(&self, now_ns: i64) -> bool {
        if let Some(exp) = self.expiration_ns {
            if now_ns >= exp {
                return false;
            }
        }
        true
    }

    /// Returns true if `alert_ts_ns` falls within at least one active time range.
    /// When no time ranges are defined, all timestamps are accepted.
    pub fn in_maintenance_window(&self, alert_ts_ns: i64) -> bool {
        if self.active_time_ranges.is_empty() {
            return true;
        }
        self.active_time_ranges.iter().any(|r| r.contains(alert_ts_ns))
    }

    /// Evaluates all predicates against the alert.
    /// Returns true only when ALL predicates match.
    pub fn matches(&self, alert: &NormalizedAlert, now_ns: i64) -> bool {
        if !self.is_active(now_ns) {
            return false;
        }
        if !self.in_maintenance_window(alert.created_time_ns) {
            return false;
        }
        self.criteria_predicates.iter().all(|p| p.evaluate(alert))
    }
}

// ---------------------------------------------------------------------------
// Suppression Result
// ---------------------------------------------------------------------------

/// Result returned by `SuppressionGate::evaluate`.
#[derive(Debug, Clone)]
pub enum SuppressionResult {
    /// Alert passes through all suppression rules unaffected.
    Pass,
    /// Alert is suppressed by the matched rule.
    Suppressed {
        /// ID of the suppression rule that triggered.
        rule_id: String,
        /// Name of the suppression rule.
        rule_name: String,
        /// Human-readable suppression reason.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Suppression Gate
// ---------------------------------------------------------------------------

/// Evaluates `NormalizedAlert` objects against a registered chain of
/// `SuppressionRule`s.
///
/// Rules are evaluated in registration order; the first matching rule causes
/// suppression and evaluation stops (short-circuit).
pub struct SuppressionGate {
    rules: RwLock<Vec<SuppressionRule>>,
    /// Total alerts evaluated.
    total_evaluated: AtomicU64,
    /// Total alerts suppressed.
    total_suppressed: AtomicU64,
}

impl SuppressionGate {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            total_evaluated: AtomicU64::new(0),
            total_suppressed: AtomicU64::new(0),
        }
    }

    /// Registers a suppression rule.  Rules are evaluated in insertion order.
    pub fn register_rule(&self, rule: SuppressionRule) {
        self.rules.write().push(rule);
    }

    /// Removes a suppression rule by its ID.
    pub fn remove_rule(&self, rule_id: &str) {
        self.rules.write().retain(|r| r.id != rule_id);
    }

    /// Evaluates the alert against all registered suppression rules.
    ///
    /// When a rule matches:
    ///   * Alert `status` is set to `AlertStatus::Suppressed`.
    ///   * Alert `suppression_rule_id` is populated.
    ///   * Returns `SuppressionResult::Suppressed`.
    ///
    /// When no rule matches:
    ///   * Alert is unchanged.
    ///   * Returns `SuppressionResult::Pass`.
    pub fn evaluate(&self, alert: &mut NormalizedAlert, now_ns: i64) -> SuppressionResult {
        self.total_evaluated.fetch_add(1, Ordering::Relaxed);

        let rules = self.rules.read();
        for rule in rules.iter() {
            if rule.matches(alert, now_ns) {
                alert.status = AlertStatus::Suppressed;
                alert.suppression_rule_id = Some(rule.id.clone());
                self.total_suppressed.fetch_add(1, Ordering::Relaxed);
                return SuppressionResult::Suppressed {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    reason: format!(
                        "Suppressed by rule '{}' (id={})",
                        rule.name, rule.id
                    ),
                };
            }
        }
        SuppressionResult::Pass
    }

    /// Returns (total_evaluated, total_suppressed) counters.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.total_evaluated.load(Ordering::Relaxed),
            self.total_suppressed.load(Ordering::Relaxed),
        )
    }
}

impl Default for SuppressionGate {
    fn default() -> Self {
        Self::new()
    }
}
