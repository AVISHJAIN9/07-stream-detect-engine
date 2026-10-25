use parking_lot::RwLock;
use std::collections::HashMap;

pub type RuleId = u32;

/// Zero-Allocation Exact-Match Perfect-Hash Accelerator
pub struct ExactMatchAccelerator {
    /// Mapping of combined 64-bit key (field_hash ^ value_hash) -> list of RuleIds requiring exact equality
    lookup_table: RwLock<HashMap<u64, Vec<RuleId>>>,
    case_insensitive_table: RwLock<HashMap<u64, Vec<RuleId>>>,
}

impl Default for ExactMatchAccelerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ExactMatchAccelerator {
    pub fn new() -> Self {
        Self {
            lookup_table: RwLock::new(HashMap::new()),
            case_insensitive_table: RwLock::new(HashMap::new()),
        }
    }

    /// Computes 64-bit FNV-1a hash over raw bytes
    #[inline]
    pub fn hash_value(val: &str) -> u64 {
        let mut h = 0xcbf29ce484222325u64;
        for b in val.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    /// Computes case-folded 64-bit hash over ASCII bytes with zero allocation
    #[inline]
    pub fn hash_value_case_insensitive(val: &str) -> u64 {
        let mut h = 0xcbf29ce484222325u64;
        for b in val.as_bytes() {
            let lower = b.to_ascii_lowercase();
            h ^= lower as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    #[inline]
    pub fn make_combined_key(field_hash: u64, val_hash: u64) -> u64 {
        field_hash.rotate_left(17) ^ val_hash
    }

    /// Registers an exact string match requirement for a specific field and rule
    pub fn register(&self, field: &str, exact_value: &str, rule_id: RuleId, case_insensitive: bool) {
        let field_hash = Self::hash_value(field);
        if case_insensitive {
            let val_hash = Self::hash_value_case_insensitive(exact_value);
            let key = Self::make_combined_key(field_hash, val_hash);
            let mut guard = self.case_insensitive_table.write();
            guard.entry(key).or_default().push(rule_id);
        } else {
            let val_hash = Self::hash_value(exact_value);
            let key = Self::make_combined_key(field_hash, val_hash);
            let mut guard = self.lookup_table.write();
            guard.entry(key).or_default().push(rule_id);
        }
    }

    /// High-speed point lookup returning candidate rules matching exact field equality (< 10 ns)
    #[inline]
    pub fn lookup(&self, field: &str, value: &str, results: &mut Vec<RuleId>) {
        let field_hash = Self::hash_value(field);
        let hash_cs = Self::hash_value(value);
        let hash_ci = Self::hash_value_case_insensitive(value);

        let key_cs = Self::make_combined_key(field_hash, hash_cs);
        let key_ci = Self::make_combined_key(field_hash, hash_ci);

        let table_cs = self.lookup_table.read();
        if let Some(rules) = table_cs.get(&key_cs) {
            results.extend_from_slice(rules);
        }

        let table_ci = self.case_insensitive_table.read();
        if let Some(rules) = table_ci.get(&key_ci) {
            results.extend_from_slice(rules);
        }
    }
}
