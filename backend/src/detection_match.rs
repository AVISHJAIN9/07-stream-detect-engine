use crate::dedup_key_generator::{Murmur3Hasher64, UUIDv7Generator};
use crate::canonical_normalizer::CanonicalEvent;
use crate::types::ValueVariant;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Severity level
// ---------------------------------------------------------------------------

/// Detection severity levels ordered from lowest to highest impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    /// Parses a severity level from a string (case-insensitive).
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" | "med" => Self::Medium,
            _ => Self::Low,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Compiled Rule metadata stub (used by DetectionMatchFactory)
// ---------------------------------------------------------------------------

/// Minimal compiled rule representation carrying the fields required to
/// construct a canonical `DetectionMatch`.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule_id: String,
    pub rule_title: String,
    pub severity: Severity,
    pub tags: Vec<String>,
    pub grouping_keys: Vec<String>,
}

impl CompiledRule {
    pub fn new(
        rule_id: impl Into<String>,
        rule_title: impl Into<String>,
        severity: Severity,
        tags: Vec<String>,
        grouping_keys: Vec<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_title: rule_title.into(),
            severity,
            tags,
            grouping_keys,
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical Detection Match Record
// ---------------------------------------------------------------------------

/// The canonical detection match envelope produced whenever a compiled rule
/// fires against a triggering event.
///
/// Carries:
/// * A time-ordered UUIDv7 `match_id` for global deduplication.
/// * Full rule metadata: `rule_id`, `rule_title`, `severity`, `tags`.
/// * The exact nanosecond-precision detection timestamp.
/// * The `entity_id` of the affected entity.
/// * The complete set of `triggering_events` that caused the rule to fire
///   (causal lineage / provenance chain).
/// * A `context_attributes` flat-map of enriched detection context.
/// * A `suppression_fingerprint` for alert deduplication (Feature 61).
#[derive(Debug, Clone)]
pub struct DetectionMatch {
    /// Time-ordered globally unique identifier (UUIDv7).
    pub match_id: Uuid,
    /// Sigma / DSL rule identifier.
    pub rule_id: String,
    /// Human-readable rule title.
    pub rule_title: String,
    /// Detection severity level.
    pub severity: Severity,
    /// Rule classification tags (e.g. `["T1059", "execution"]`).
    pub tags: Vec<String>,
    /// Nanosecond-precision detection timestamp (Unix epoch).
    pub detection_timestamp_ns: i64,
    /// Entity (host, user, account, …) on which the rule fired.
    pub entity_id: String,
    /// Ordered list of triggering canonical events (causal provenance chain).
    pub triggering_events: Vec<CanonicalEvent>,
    /// Enriched key-value context attributes attached at detection time.
    pub context_attributes: HashMap<String, ValueVariant>,
    /// 64-bit suppression fingerprint: `H(rule_id ‖ entity_id ‖ grouping_keys)`.
    pub suppression_fingerprint: u64,
}

// ---------------------------------------------------------------------------
// Context map type alias
// ---------------------------------------------------------------------------

/// Enriched context attributes map passed into `DetectionMatchFactory`.
pub type ContextMap = HashMap<String, ValueVariant>;

// ---------------------------------------------------------------------------
// Fingerprint helper (standalone function for use outside the factory)
// ---------------------------------------------------------------------------

/// Computes the canonical 64-bit suppression fingerprint for a match record.
///
/// Inputs:
/// * `rule_id` – Sigma / DSL rule identifier.
/// * `entity_id` – Affected entity identifier.
/// * `grouping_keys` – Sorted slice of grouping dimension values that further
///   qualify the alert window (e.g. destination IP, username).
pub fn compute_suppression_fingerprint(
    rule_id: &str,
    entity_id: &str,
    grouping_keys: &[&str],
) -> u64 {
    let mut h = Murmur3Hasher64::new(0xDEAD_BEEF_CAFE_BABEu64);
    h.write_str(rule_id);
    h.write_str("\x00");
    h.write_str(entity_id);
    h.write_str("\x00");
    // Stable sort guarantees order-invariance without requiring the caller to
    // pre-sort.
    let mut sorted: Vec<&str> = grouping_keys.to_vec();
    sorted.sort_unstable();
    for k in &sorted {
        h.write_str(k);
        h.write_str("\x01");
    }
    h.finish()
}

// ---------------------------------------------------------------------------
// Detection Match Factory
// ---------------------------------------------------------------------------

/// Instantiates canonical `DetectionMatch` envelopes at sub-100 ns latency.
///
/// # Design
/// * Uses a pre-allocated `UUIDv7Generator` for time-ordered match IDs.
/// * Computes the suppression fingerprint in-line using the same Murmur3 path
///   as `AlertDeduplicator`.
/// * Clones only the minimum required fields from the triggering event into
///   the causal lineage envelope.
/// * Context attributes are moved (not cloned) when possible.
pub struct DetectionMatchFactory {
    uuid_gen: UUIDv7Generator,
}

impl DetectionMatchFactory {
    pub fn new() -> Self {
        Self { uuid_gen: UUIDv7Generator::new() }
    }

    /// Creates a `DetectionMatch` record from a fired rule, the triggering
    /// event, and the additional detection context map.
    ///
    /// # Arguments
    /// * `rule` – Reference to the compiled rule that fired.
    /// * `triggering_event` – The canonical event that caused the rule to
    ///   evaluate to `true`.
    /// * `context` – Additional enrichment attributes collected during rule
    ///   evaluation (e.g. looked-up threat intelligence, resolved hostnames).
    pub fn create_match(
        &self,
        rule: &CompiledRule,
        triggering_event: &CanonicalEvent,
        context: ContextMap,
    ) -> DetectionMatch {
        let match_id = self.uuid_gen.generate();

        let detection_timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        // Build grouping key values from the rule's grouping_keys list,
        // resolving each one against the triggering event's attributes.
        let grouping_values: Vec<String> = rule
            .grouping_keys
            .iter()
            .map(|k| {
                triggering_event
                    .attributes
                    .get(k)
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            })
            .collect();

        let grouping_key_refs: Vec<&str> = grouping_values.iter().map(|s| s.as_str()).collect();

        let suppression_fingerprint = compute_suppression_fingerprint(
            &rule.rule_id,
            &triggering_event.entity_id,
            &grouping_key_refs,
        );

        DetectionMatch {
            match_id,
            rule_id: rule.rule_id.clone(),
            rule_title: rule.rule_title.clone(),
            severity: rule.severity,
            tags: rule.tags.clone(),
            detection_timestamp_ns,
            entity_id: triggering_event.entity_id.clone(),
            triggering_events: vec![triggering_event.clone()],
            context_attributes: context,
            suppression_fingerprint,
        }
    }

    /// Variant that accepts multiple triggering events for multi-event
    /// correlation rules (e.g. sequence patterns).
    pub fn create_correlated_match(
        &self,
        rule: &CompiledRule,
        triggering_events: Vec<CanonicalEvent>,
        primary_entity_id: &str,
        context: ContextMap,
    ) -> DetectionMatch {
        let match_id = self.uuid_gen.generate();

        let detection_timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        // For correlated matches use the primary_entity_id directly for the
        // fingerprint; grouping values are empty (the rule's grouping_keys are
        // not meaningful across heterogeneous events).
        let suppression_fingerprint =
            compute_suppression_fingerprint(&rule.rule_id, primary_entity_id, &[]);

        DetectionMatch {
            match_id,
            rule_id: rule.rule_id.clone(),
            rule_title: rule.rule_title.clone(),
            severity: rule.severity,
            tags: rule.tags.clone(),
            detection_timestamp_ns,
            entity_id: primary_entity_id.to_string(),
            triggering_events,
            context_attributes: context,
            suppression_fingerprint,
        }
    }
}

impl Default for DetectionMatchFactory {
    fn default() -> Self {
        Self::new()
    }
}
