use std::collections::VecDeque;

pub type PatternMatchId = u32;

/// Dense Automaton State Node
#[derive(Debug, Clone)]
pub struct AutomatonState {
    /// Dense byte transition table (256 transitions per state)
    pub transitions: Vec<u32>,
    /// Failure link pointing to the longest proper suffix state
    pub fail: u32,
    /// Pattern match IDs emitted upon entering this state
    pub outputs: Vec<PatternMatchId>,
}

impl AutomatonState {
    pub fn new() -> Self {
        Self {
            transitions: vec![0; 256],
            fail: 0,
            outputs: Vec::new(),
        }
    }
}

/// High-Performance Aho-Corasick Multi-Pattern Substring Matcher
#[derive(Debug, Clone)]
pub struct AhoCorasick {
    states: Vec<AutomatonState>,
    pattern_count: usize,
    case_insensitive: bool,
    is_compiled: bool,
}

impl Default for AhoCorasick {
    fn default() -> Self {
        Self::new(false)
    }
}

impl AhoCorasick {
    pub fn new(case_insensitive: bool) -> Self {
        let mut ac = Self {
            states: Vec::with_capacity(1024),
            pattern_count: 0,
            case_insensitive,
            is_compiled: false,
        };
        // State 0 is root
        ac.states.push(AutomatonState::new());
        ac
    }

    /// Adds a pattern string associated with a match ID
    pub fn add_pattern(&mut self, pattern: &[u8], match_id: PatternMatchId) {
        if pattern.is_empty() {
            return;
        }

        let mut current_state = 0usize;
        for &byte in pattern {
            let b = if self.case_insensitive {
                byte.to_ascii_lowercase() as usize
            } else {
                byte as usize
            };

            let next_state = self.states[current_state].transitions[b];
            if next_state == 0 {
                let new_state_id = self.states.len() as u32;
                self.states.push(AutomatonState::new());
                self.states[current_state].transitions[b] = new_state_id;
                current_state = new_state_id as usize;
            } else {
                current_state = next_state as usize;
            }
        }

        self.states[current_state].outputs.push(match_id);
        self.pattern_count += 1;
        self.is_compiled = false;
    }

    /// Compiles BFS failure transitions and flattens dictionary output links
    pub fn build(&mut self) {
        let mut queue = VecDeque::new();

        // Level 1: states directly adjacent to root
        for b in 0..256 {
            let next = self.states[0].transitions[b];
            if next != 0 {
                self.states[next as usize].fail = 0;
                queue.push_back(next);
            }
        }

        // BFS traversal for deeper levels
        while let Some(r) = queue.pop_front() {
            let r_idx = r as usize;

            for b in 0..256 {
                let u = self.states[r_idx].transitions[b];
                if u != 0 {
                    let u_idx = u as usize;
                    queue.push_back(u);

                    let mut v = self.states[r_idx].fail;
                    while v != 0 && self.states[v as usize].transitions[b] == 0 {
                        v = self.states[v as usize].fail;
                    }

                    let fail_target = self.states[v as usize].transitions[b];
                    self.states[u_idx].fail = fail_target;

                    // Merge outputs from the failure target
                    if fail_target != 0 {
                        let inherited_outputs = self.states[fail_target as usize].outputs.clone();
                        self.states[u_idx].outputs.extend(inherited_outputs);
                    }
                } else {
                    // Flattened transition: shortcut to failure state's transition
                    let fail_state = self.states[r_idx].fail as usize;
                    self.states[r_idx].transitions[b] = self.states[fail_state].transitions[b];
                }
            }
        }

        self.is_compiled = true;
    }

    /// Scans a byte stream in a single linear pass O(N), calling callback for each pattern match
    #[inline]
    pub fn find_all<F>(&self, haystack: &[u8], mut callback: F)
    where
        F: FnMut(usize, PatternMatchId),
    {
        let mut state = 0u32;
        for (i, &byte) in haystack.iter().enumerate() {
            let b = if self.case_insensitive {
                byte.to_ascii_lowercase() as usize
            } else {
                byte as usize
            };

            state = self.states[state as usize].transitions[b];

            if !self.states[state as usize].outputs.is_empty() {
                for &match_id in &self.states[state as usize].outputs {
                    callback(i, match_id);
                }
            }
        }
    }

    /// Returns the number of distinct patterns compiled into this automaton
    pub fn pattern_count(&self) -> usize {
        self.pattern_count
    }

    /// Returns the total state count
    pub fn state_count(&self) -> usize {
        self.states.len()
    }
}
