use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use crate::canonical_normalizer::CanonicalEvent;
use crate::types::ValueVariant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFieldPath {
    pub original_field: String,
    pub canonical_path: String,
    pub path_segments: Vec<String>,
}

pub struct FieldResolver {
    alias_map: Arc<RwLock<HashMap<String, ResolvedFieldPath>>>,
}

impl Default for FieldResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldResolver {
    pub fn new() -> Self {
        let mut map = HashMap::new();

        // Populate standard Sigma / OS / EDR taxonomy aliases
        let standard_mappings = vec![
            ("CommandLine", "process.command_line"),
            ("commandline", "process.command_line"),
            ("cmdline", "process.command_line"),
            ("ParentCommandLine", "process.parent.command_line"),
            ("parent_cmdline", "process.parent.command_line"),
            ("Image", "process.executable"),
            ("image", "process.executable"),
            ("ParentImage", "process.parent.executable"),
            ("ProcessId", "process.pid"),
            ("pid", "process.pid"),
            ("ParentProcessId", "process.parent.pid"),
            ("ppid", "process.parent.pid"),
            ("User", "user.name"),
            ("user", "user.name"),
            ("TargetFilename", "file.path"),
            ("DestinationIp", "destination.ip"),
            ("dst_ip", "destination.ip"),
            ("SourceIp", "source.ip"),
            ("src_ip", "source.ip"),
            ("DestinationPort", "destination.port"),
            ("dst_port", "destination.port"),
            ("SourcePort", "source.port"),
            ("src_port", "source.port"),
            ("Protocol", "network.protocol"),
            ("protocol", "network.protocol"),
            ("Hashes", "file.hash.sha256"),
            ("sha256", "file.hash.sha256"),
        ];

        for (alias, canonical) in standard_mappings {
            let segments: Vec<String> = canonical.split('.').map(|s| s.to_string()).collect();
            map.insert(
                alias.to_string(),
                ResolvedFieldPath {
                    original_field: alias.to_string(),
                    canonical_path: canonical.to_string(),
                    path_segments: segments,
                },
            );
        }

        Self {
            alias_map: Arc::new(RwLock::new(map)),
        }
    }

    pub fn register_alias(&self, alias: &str, canonical_path: &str) {
        let segments: Vec<String> = canonical_path.split('.').map(|s| s.to_string()).collect();
        self.alias_map.write().insert(
            alias.to_string(),
            ResolvedFieldPath {
                original_field: alias.to_string(),
                canonical_path: canonical_path.to_string(),
                path_segments: segments,
            },
        );
    }

    /// Resolves field name or alias into a canonical dotted path (< 30 ns)
    #[inline(always)]
    pub fn resolve(&self, field_name: &str) -> ResolvedFieldPath {
        let map = self.alias_map.read();
        if let Some(resolved) = map.get(field_name) {
            resolved.clone()
        } else {
            let segments: Vec<String> = field_name.split('.').map(|s| s.to_string()).collect();
            ResolvedFieldPath {
                original_field: field_name.to_string(),
                canonical_path: field_name.to_string(),
                path_segments: segments,
            }
        }
    }

    /// Extracts value from CanonicalEvent using resolved field path
    pub fn extract_field_value<'a>(
        &self,
        event: &'a CanonicalEvent,
        resolved: &ResolvedFieldPath,
    ) -> Option<&'a ValueVariant> {
        // 1. Direct top-level attribute check with original name
        if let Some(val) = event.attributes.get(&resolved.original_field) {
            return Some(val);
        }

        // 2. Direct top-level attribute check with canonical dotted path
        if let Some(val) = event.attributes.get(&resolved.canonical_path) {
            return Some(val);
        }

        // 3. Fallback to common top-level canonical event fields
        if resolved.canonical_path == "source" {
            // Virtual ValueVariant wrapper or checked at rule eval
            return None;
        }

        // 4. Nested Map traversal for dotted segments (e.g. process -> command_line)
        if resolved.path_segments.len() > 1 {
            let mut current = event.attributes.get(&resolved.path_segments[0]);
            for seg in &resolved.path_segments[1..] {
                match current {
                    Some(ValueVariant::Map(map)) => {
                        current = map.get(seg);
                    }
                    _ => return None,
                }
            }
            return current;
        }

        None
    }
}
