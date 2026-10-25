use crate::aho_corasick::{AhoCorasick, PatternMatchId};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

pub type RuleId = String;
pub type SearchId = String;

/// Cross-Rule Field-Partitioned Shared Automata Registry
pub struct FieldAutomataRegistry {
    /// Mapping of field canonical path to compiled AhoCorasick automaton
    automata: RwLock<HashMap<String, Arc<AhoCorasick>>>,
    /// Reverse mapping from (Field, PatternMatchId) -> list of (RuleId, SearchId)
    pattern_rule_map: RwLock<HashMap<(String, PatternMatchId), Vec<(RuleId, SearchId)>>>,
}

impl Default for FieldAutomataRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldAutomataRegistry {
    pub fn new() -> Self {
        Self {
            automata: RwLock::new(HashMap::new()),
            pattern_rule_map: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a set of patterns for a specific field across rules and builds the unified automaton
    pub fn register_field_patterns(
        &self,
        field: &str,
        patterns: &[(&[u8], RuleId, SearchId)],
        case_insensitive: bool,
    ) {
        let mut ac = AhoCorasick::new(case_insensitive);
        let mut match_map: HashMap<PatternMatchId, Vec<(RuleId, SearchId)>> = HashMap::new();

        for (idx, &(pat, ref rule_id, ref search_id)) in patterns.iter().enumerate() {
            let match_id = idx as PatternMatchId;
            ac.add_pattern(pat, match_id);
            match_map
                .entry(match_id)
                .or_default()
                .push((rule_id.clone(), search_id.clone()));
        }

        ac.build();

        let mut automata_guard = self.automata.write();
        automata_guard.insert(field.to_string(), Arc::new(ac));

        let mut map_guard = self.pattern_rule_map.write();
        for (match_id, rules) in match_map {
            map_guard.insert((field.to_string(), match_id), rules);
        }
    }

    /// Scans an event field payload with the shared automaton and fires all matching (RuleId, SearchId) pairs
    pub fn scan_field<F>(&self, field: &str, payload: &[u8], mut match_collector: F)
    where
        F: FnMut(&str, &str, usize),
    {
        let ac_opt = {
            let automata_guard = self.automata.read();
            automata_guard.get(field).cloned()
        };

        if let Some(ac) = ac_opt {
            let map_guard = self.pattern_rule_map.read();
            ac.find_all(payload, |offset, match_id| {
                if let Some(rules) = map_guard.get(&(field.to_string(), match_id)) {
                    for (rule_id, search_id) in rules {
                        match_collector(rule_id, search_id, offset);
                    }
                }
            });
        }
    }

    /// Returns the number of distinct field automata registered
    pub fn field_count(&self) -> usize {
        self.automata.read().len()
    }
}
