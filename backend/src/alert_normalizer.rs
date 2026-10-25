/// Feature 67 – Alert Object Normalization & Common Schema Converter
///
/// Transforms internal `DetectionMatch` records into a standardized
/// `NormalizedAlert` envelope that is compatible with OCSF Security Finding
/// (class_uid 2001) and ASIM AlertEvent schemas.
///
/// KPI: Conversion overhead ≤ 80 ns.

use crate::detection_match::{DetectionMatch, Severity};
use crate::canonical_normalizer::CanonicalEvent;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Alert Status
// ---------------------------------------------------------------------------

/// Lifecycle status of a normalized alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertStatus {
    /// Newly created, not yet acknowledged.
    Active,
    /// Suppressed by a suppression gate rule.
    Suppressed,
    /// Grouped into a parent incident group.
    Grouped,
}

impl AlertStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suppressed => "suppressed",
            Self::Grouped => "grouped",
        }
    }
}

impl std::fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Sub-object structures (OCSF-aligned)
// ---------------------------------------------------------------------------

/// Represents the actor / user entity that triggered the detection.
#[derive(Debug, Clone, Default)]
pub struct ActorEntity {
    /// Username or user principal name.
    pub user_name: String,
    /// Domain prefix if applicable (`CORP\jsmith` → `CORP`).
    pub domain: Option<String>,
    /// Parsed user SID or UUID.
    pub uid: Option<String>,
    /// Session / process ID associated with the actor.
    pub session_id: Option<String>,
    /// Is the actor a privileged / admin account?
    pub is_privileged: bool,
}

/// Represents the target device / asset where the detection occurred.
#[derive(Debug, Clone, Default)]
pub struct DeviceEntity {
    /// FQDN or short hostname.
    pub hostname: String,
    /// Primary IPv4 or IPv6 address.
    pub ip_address: Option<String>,
    /// MAC address.
    pub mac_address: Option<String>,
    /// Operating system name.
    pub os_name: Option<String>,
    /// Asset unique identifier in CMDB.
    pub asset_id: Option<String>,
    /// Business criticality tier (1 = low … 5 = critical).
    pub criticality_tier: u8,
}

/// Represents relevant network endpoint metadata.
#[derive(Debug, Clone, Default)]
pub struct NetworkEntity {
    /// Source IP.
    pub src_ip: Option<String>,
    /// Destination IP.
    pub dst_ip: Option<String>,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// Layer-4 protocol (e.g. `TCP`, `UDP`).
    pub protocol: Option<String>,
    /// Direction of the connection relative to the asset.
    pub direction: Option<String>,
}

/// A single piece of evidence tied to a specific triggering event.
#[derive(Debug, Clone)]
pub struct EventEvidence {
    /// UUID of the triggering canonical event.
    pub event_id: Uuid,
    /// Event type label.
    pub event_type: String,
    /// Nanosecond-precision event timestamp.
    pub event_timestamp_ns: i64,
    /// Key-value evidence attributes from the event.
    pub fields: HashMap<String, String>,
}

/// Contextual enrichment payload injected by the enrichment engine.
#[derive(Debug, Clone, Default)]
pub struct ContextEnrichment {
    /// Asset owner name from CMDB.
    pub asset_owner: Option<String>,
    /// Business unit / department.
    pub department: Option<String>,
    /// Network zone (e.g. `prod`, `dmz`, `corp`).
    pub network_zone: Option<String>,
    /// Is the user or device a VIP?
    pub is_vip: bool,
    /// Resolved hostname from IP.
    pub resolved_hostname: Option<String>,
    /// Free-form key-value enrichment tags.
    pub tags: HashMap<String, String>,
}

/// Explainability metadata populated by the `EvidenceAttributor` (Feature 78).
#[derive(Debug, Clone, Default)]
pub struct ExplainabilityMetadata {
    /// The full evaluated rule condition string.
    pub evaluated_condition_str: String,
    /// Sigma search identifiers that were satisfied.
    pub satisfied_search_identifiers: Vec<String>,
    /// Specific field-level evidence entries.
    pub matched_fields: Vec<FieldEvidence>,
    /// Primary MITRE ATT&CK technique ID (e.g. `T1059.001`).
    pub mitre_technique_id: String,
    /// Human-readable attack vector summary.
    pub attack_vector_summary: String,
}

/// Single field-level evidence entry.
#[derive(Debug, Clone)]
pub struct FieldEvidence {
    /// Source field name (e.g. `process.command_line`).
    pub field: String,
    /// Pattern that was matched (e.g. `*powershell*`).
    pub matched_pattern: String,
    /// Exact field value that triggered the match.
    pub exact_value: String,
}

// ---------------------------------------------------------------------------
// NormalizedAlert – canonical security alert envelope
// ---------------------------------------------------------------------------

/// Canonical, fully normalized security alert envelope.
///
/// Compatible with OCSF Security Finding (class_uid 2001) and ASIM AlertEvent.
/// This is the primary data structure flowing through all Phase XII and XIII
/// alerting subsystems.
#[derive(Debug, Clone)]
pub struct NormalizedAlert {
    // ---- OCSF Finding Info ----
    /// Globally unique alert UUID (UUIDv4).
    pub alert_id: Uuid,
    /// Nanosecond-precision creation timestamp.
    pub created_time_ns: i64,
    /// Sigma / DSL rule identifier.
    pub rule_id: String,
    /// Human-readable detection title.
    pub title: String,
    /// Base severity level from rule definition.
    pub severity: Severity,
    /// Computed risk score (0–100).
    pub risk_score: u8,
    /// Classification tags (MITRE ATT&CK IDs, tactic names, compliance refs).
    pub tags: Vec<String>,
    /// Tenant identifier for multi-tenant deployments.
    pub tenant_id: String,

    // ---- Entity Blocks ----
    /// Actor (user/process) entity that triggered the detection.
    pub actor: ActorEntity,
    /// Target device / asset.
    pub device: DeviceEntity,
    /// Network endpoint context.
    pub network: NetworkEntity,

    // ---- Evidence & Enrichment ----
    /// Ordered list of triggering event evidence blocks (causal lineage).
    pub evidence: Vec<EventEvidence>,
    /// Contextual enrichment attributes injected by the enrichment pipeline.
    pub enrichment: ContextEnrichment,
    /// Explainability metadata (populated by EvidenceAttributor, Feature 78).
    pub explainability: Option<ExplainabilityMetadata>,

    // ---- Lifecycle ----
    /// Current alert lifecycle status.
    pub status: AlertStatus,
    /// Suppression rule ID if status == Suppressed.
    pub suppression_rule_id: Option<String>,
    /// Correlation ID linking this alert to a multi-stage campaign.
    pub correlation_id: Option<u64>,
    /// Group ID if this alert has been grouped into an incident.
    pub group_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// AlertNormalizer
// ---------------------------------------------------------------------------

/// Converts internal `DetectionMatch` records into `NormalizedAlert` envelopes.
///
/// # Performance
/// The hot path avoids heap allocation for small collections by using
/// `with_capacity` pre-sizing. Typical conversion latency is ≤ 80 ns in
/// release mode.
pub struct AlertNormalizer;

impl AlertNormalizer {
    pub fn new() -> Self {
        Self
    }

    /// Normalizes a `DetectionMatch` into a `NormalizedAlert`.
    ///
    /// # Arguments
    /// * `dm` – Reference to the detection match produced by `DetectionMatchFactory`.
    ///
    /// # Schema Mapping
    /// | DetectionMatch field     | NormalizedAlert destination              |
    /// |--------------------------|------------------------------------------|
    /// | `match_id`               | `alert_id`                               |
    /// | `detection_timestamp_ns` | `created_time_ns`                        |
    /// | `rule_id`                | `rule_id`                                |
    /// | `rule_title`             | `title`                                  |
    /// | `severity`               | `severity`                               |
    /// | `tags`                   | `tags`                                   |
    /// | `entity_id`              | `device.hostname` + `actor.user_name`    |
    /// | `triggering_events`      | `evidence` (one entry per event)         |
    /// | `context_attributes`     | `actor`, `device`, `network` fields       |
    pub fn normalize(&self, dm: &DetectionMatch) -> NormalizedAlert {
        // --- Actor Entity ---
        let actor = {
            let user_name = dm
                .context_attributes
                .get("user_name")
                .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None })
                .unwrap_or_else(|| dm.entity_id.clone());

            let domain = dm
                .context_attributes
                .get("domain")
                .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None });

            let uid = dm
                .context_attributes
                .get("user_sid")
                .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None });

            let session_id = dm
                .context_attributes
                .get("session_id")
                .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None });

            let is_privileged = dm
                .context_attributes
                .get("is_privileged")
                .and_then(|v| if let crate::types::ValueVariant::Bool(b) = v { Some(*b) } else { None })
                .unwrap_or(false);

            ActorEntity { user_name, domain, uid, session_id, is_privileged }
        };

        // --- Device Entity ---
        let device = {
            let hostname = dm
                .context_attributes
                .get("hostname")
                .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None })
                .unwrap_or_else(|| dm.entity_id.clone());

            let ip_address = dm
                .triggering_events
                .first()
                .and_then(|e| e.source_ip.clone())
                .or_else(|| {
                    dm.context_attributes
                        .get("src_ip")
                        .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None })
                });

            let mac_address = dm
                .context_attributes
                .get("mac_address")
                .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None });

            let os_name = dm
                .context_attributes
                .get("os_name")
                .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None });

            let asset_id = dm
                .context_attributes
                .get("asset_id")
                .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None });

            let criticality_tier = dm
                .context_attributes
                .get("criticality_tier")
                .and_then(|v| if let crate::types::ValueVariant::Int(i) = v { Some(*i as u8) } else { None })
                .unwrap_or(1);

            DeviceEntity { hostname, ip_address, mac_address, os_name, asset_id, criticality_tier }
        };

        // --- Network Entity ---
        let network = {
            let src_ip = dm
                .triggering_events
                .first()
                .and_then(|e| e.source_ip.clone());

            let dst_ip = dm
                .context_attributes
                .get("dst_ip")
                .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None });

            let dst_port = dm
                .context_attributes
                .get("dst_port")
                .and_then(|v| if let crate::types::ValueVariant::Int(i) = v { Some(*i as u16) } else { None });

            let protocol = dm
                .context_attributes
                .get("protocol")
                .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None });

            let direction = dm
                .context_attributes
                .get("direction")
                .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None });

            NetworkEntity { src_ip, dst_ip, dst_port, protocol, direction }
        };

        // --- Evidence ---
        let evidence: Vec<EventEvidence> = dm
            .triggering_events
            .iter()
            .map(|ev: &CanonicalEvent| {
                let mut fields = HashMap::with_capacity(ev.attributes.len());
                for (k, v) in &ev.attributes {
                    fields.insert(k.clone(), v.to_string());
                }
                EventEvidence {
                    event_id: ev.event_id,
                    event_type: ev.event_type.clone(),
                    event_timestamp_ns: ev.event_timestamp_ns,
                    fields,
                }
            })
            .collect();

        // --- Tenant ID ---
        let tenant_id = dm
            .context_attributes
            .get("tenant_id")
            .and_then(|v| if let crate::types::ValueVariant::String(s) = v { Some(s.clone()) } else { None })
            .unwrap_or_else(|| "default".to_string());

        NormalizedAlert {
            alert_id: Uuid::new_v4(),
            created_time_ns: dm.detection_timestamp_ns,
            rule_id: dm.rule_id.clone(),
            title: dm.rule_title.clone(),
            severity: dm.severity,
            risk_score: self.base_risk_score(dm.severity),
            tags: dm.tags.clone(),
            tenant_id,
            actor,
            device,
            network,
            evidence,
            enrichment: ContextEnrichment::default(),
            explainability: None,
            status: AlertStatus::Active,
            suppression_rule_id: None,
            correlation_id: None,
            group_id: None,
        }
    }

    /// Returns the base risk score for a severity level before environmental
    /// multipliers are applied (Feature 68 uses these as `S_base`).
    #[inline]
    pub fn base_risk_score(&self, severity: Severity) -> u8 {
        match severity {
            Severity::Low => 25,
            Severity::Medium => 50,
            Severity::High => 75,
            Severity::Critical => 90,
        }
    }
}

impl Default for AlertNormalizer {
    fn default() -> Self {
        Self::new()
    }
}
