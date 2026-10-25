/// Feature 69 – Contextual Alert Enrichment & Entity Resolution
///
/// Provides thread-safe in-memory CMDB / IAM directory caches and an
/// `AlertEnrichmentEngine` that decorates `NormalizedAlert` objects with
/// resolved asset and identity metadata.
///
/// KPI: Enrichment lookup latency ≤ 50 µs per alert.

use crate::alert_normalizer::{ContextEnrichment, NormalizedAlert};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Asset Directory (CMDB)
// ---------------------------------------------------------------------------

/// Asset / host record sourced from a CMDB or asset inventory.
#[derive(Debug, Clone)]
pub struct AssetRecord {
    /// Primary identifier used for lookup (hostname or IP).
    pub host_key: String,
    /// Canonical hostname (FQDN or short).
    pub canonical_hostname: String,
    /// Asset owner name.
    pub owner: String,
    /// Business unit / department.
    pub department: String,
    /// Network zone (e.g. `prod`, `dmz`, `staging`).
    pub network_zone: String,
    /// Operating system family.
    pub os_name: String,
    /// Criticality tier (1 = low … 5 = critical crown-jewel).
    pub criticality_tier: u8,
    /// Human-readable criticality label.
    pub criticality_label: String,
    /// Whether this asset is considered VIP.
    pub is_vip: bool,
}

/// Thread-safe in-memory CMDB directory cache.
///
/// Keys are normalized to lowercase for case-insensitive lookup.
/// Both hostname and IP address may be used as lookup keys.
pub struct AssetDirectory {
    by_hostname: RwLock<HashMap<String, Arc<AssetRecord>>>,
    by_ip: RwLock<HashMap<String, Arc<AssetRecord>>>,
}

impl AssetDirectory {
    pub fn new() -> Self {
        Self {
            by_hostname: RwLock::new(HashMap::new()),
            by_ip: RwLock::new(HashMap::new()),
        }
    }

    /// Registers an asset record accessible by both hostname and IP.
    pub fn register(&self, record: AssetRecord, ip_address: Option<&str>) {
        let arc = Arc::new(record);
        let key = arc.host_key.to_lowercase();
        self.by_hostname.write().insert(key, Arc::clone(&arc));
        if let Some(ip) = ip_address {
            self.by_ip.write().insert(ip.to_string(), arc);
        }
    }

    /// Looks up an asset by hostname (case-insensitive).
    pub fn lookup_by_hostname(&self, hostname: &str) -> Option<Arc<AssetRecord>> {
        self.by_hostname.read().get(&hostname.to_lowercase()).cloned()
    }

    /// Looks up an asset by IP address.
    pub fn lookup_by_ip(&self, ip: &str) -> Option<Arc<AssetRecord>> {
        self.by_ip.read().get(ip).cloned()
    }
}

impl Default for AssetDirectory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// User Directory (IAM)
// ---------------------------------------------------------------------------

/// User / identity record sourced from IAM or Active Directory.
#[derive(Debug, Clone)]
pub struct UserRecord {
    /// Primary username / user principal name (lookup key).
    pub username: String,
    /// Display name.
    pub display_name: String,
    /// Email address.
    pub email: String,
    /// Department / business unit.
    pub department: String,
    /// Manager's username.
    pub manager: String,
    /// Privilege tier:
    ///   1 = standard, 2 = power user, 3 = admin / privileged.
    pub privilege_tier: u8,
    /// Whether this user is considered VIP (executive, security-sensitive).
    pub is_vip: bool,
    /// Whether the account is currently active.
    pub is_active: bool,
}

/// Thread-safe in-memory IAM user directory cache.
pub struct UserDirectory {
    by_username: RwLock<HashMap<String, Arc<UserRecord>>>,
}

impl UserDirectory {
    pub fn new() -> Self {
        Self { by_username: RwLock::new(HashMap::new()) }
    }

    /// Registers a user record.
    pub fn register(&self, record: UserRecord) {
        let key = record.username.to_lowercase();
        self.by_username.write().insert(key, Arc::new(record));
    }

    /// Looks up a user by username (case-insensitive).
    pub fn lookup(&self, username: &str) -> Option<Arc<UserRecord>> {
        self.by_username.read().get(&username.to_lowercase()).cloned()
    }
}

impl Default for UserDirectory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Alert Enrichment Engine
// ---------------------------------------------------------------------------

/// Contextual alert enrichment engine that queries in-memory CMDB and IAM
/// caches to decorate `NormalizedAlert` objects with asset and identity metadata.
///
/// # Enrichment Pipeline
/// 1. Resolve `alert.device.hostname` → `AssetDirectory` → populate owner,
///    department, network zone, criticality, VIP flag.
/// 2. Resolve `alert.device.ip_address` → `AssetDirectory` (fallback).
/// 3. Resolve `alert.actor.user_name` → `UserDirectory` → populate department,
///    manager, privilege tier, VIP flag.
/// 4. Merge all resolved fields into `alert.enrichment`.
pub struct AlertEnrichmentEngine {
    asset_dir: Arc<AssetDirectory>,
    user_dir: Arc<UserDirectory>,
}

impl AlertEnrichmentEngine {
    /// Creates a new enrichment engine with the given directory caches.
    pub fn new(asset_dir: Arc<AssetDirectory>, user_dir: Arc<UserDirectory>) -> Self {
        Self { asset_dir, user_dir }
    }

    /// Creates a new enrichment engine with empty directories.
    pub fn empty() -> Self {
        Self {
            asset_dir: Arc::new(AssetDirectory::new()),
            user_dir: Arc::new(UserDirectory::new()),
        }
    }

    /// Returns a reference to the asset directory for direct registration.
    pub fn asset_directory(&self) -> &AssetDirectory {
        &self.asset_dir
    }

    /// Returns a reference to the user directory for direct registration.
    pub fn user_directory(&self) -> &UserDirectory {
        &self.user_dir
    }

    /// Enriches a `NormalizedAlert` in-place with resolved CMDB and IAM metadata.
    ///
    /// Resolution priority:
    /// * Asset: hostname first, then IP fallback.
    /// * User:  actor.user_name (already normalized in alert_normalizer).
    pub fn enrich(&self, alert: &mut NormalizedAlert) {
        // --- Asset / Device Enrichment ---
        let asset_record = self
            .asset_dir
            .lookup_by_hostname(&alert.device.hostname)
            .or_else(|| {
                alert.device.ip_address.as_ref()
                    .and_then(|ip| self.asset_dir.lookup_by_ip(ip))
            });

        if let Some(asset) = asset_record {
            alert.enrichment.asset_owner = Some(asset.owner.clone());
            alert.enrichment.department = Some(asset.department.clone());
            alert.enrichment.network_zone = Some(asset.network_zone.clone());
            alert.enrichment.resolved_hostname = Some(asset.canonical_hostname.clone());
            alert.enrichment.is_vip |= asset.is_vip;

            // Update device entity with CMDB-resolved fields
            if alert.device.os_name.is_none() {
                alert.device.os_name = Some(asset.os_name.clone());
            }
            alert.device.criticality_tier = asset.criticality_tier;

            // Tag with criticality label
            alert.enrichment.tags.insert(
                "asset_criticality".to_string(),
                asset.criticality_label.clone(),
            );
        }

        // --- User / Identity Enrichment ---
        let user_record = self.user_dir.lookup(&alert.actor.user_name);

        if let Some(user) = user_record {
            alert.enrichment.tags.insert("user_display_name".to_string(), user.display_name.clone());
            alert.enrichment.tags.insert("user_email".to_string(), user.email.clone());
            alert.enrichment.tags.insert("user_department".to_string(), user.department.clone());
            alert.enrichment.tags.insert("user_manager".to_string(), user.manager.clone());
            alert.enrichment.tags.insert(
                "user_privilege_tier".to_string(),
                user.privilege_tier.to_string(),
            );
            alert.enrichment.tags.insert(
                "user_is_active".to_string(),
                user.is_active.to_string(),
            );
            alert.enrichment.is_vip |= user.is_vip;

            // Propagate privilege tier to actor entity
            alert.actor.is_privileged = user.privilege_tier >= 3;

            if alert.enrichment.department.is_none() {
                alert.enrichment.department = Some(user.department.clone());
            }

            if user.is_vip {
                alert.enrichment.tags.insert("vip_user".to_string(), "true".to_string());
            }
        }
    }
}
