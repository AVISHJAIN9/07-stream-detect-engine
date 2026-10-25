use crate::rule_ast::{ConditionExpr, RuleAST};
use crate::types::ValueVariant;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleIntegrityError {
    MaxDepthExceeded { depth: usize, limit: usize },
    ContradictoryCondition(String),
    UnreachableBranch(String),
    InvalidFieldMatcher(String),
    EmptySearchSelection(String),
}

impl fmt::Display for RuleIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaxDepthExceeded { depth, limit } => {
                write!(f, "Rule AST depth {} exceeds limit {}", depth, limit)
            }
            Self::ContradictoryCondition(msg) => {
                write!(f, "Contradictory condition detected: {}", msg)
            }
            Self::UnreachableBranch(msg) => write!(f, "Unreachable branch detected: {}", msg),
            Self::InvalidFieldMatcher(msg) => write!(f, "Invalid field matcher: {}", msg),
            Self::EmptySearchSelection(msg) => write!(f, "Empty search selection: {}", msg),
        }
    }
}

impl std::error::Error for RuleIntegrityError {}

/// Static AST Bytecode and Integrity Validator
pub struct CompiledRuleValidator {
    max_tree_depth: usize,
}

impl Default for CompiledRuleValidator {
    fn default() -> Self {
        Self {
            max_tree_depth: 64,
        }
    }
}

impl CompiledRuleValidator {
    pub fn new(max_tree_depth: usize) -> Self {
        Self { max_tree_depth }
    }

    /// Performs comprehensive static analysis on a compiled RuleAST
    pub fn validate(&self, rule: &RuleAST) -> Result<(), RuleIntegrityError> {
        // 1. Verify AST tree depth limit
        let depth = self.check_tree_depth(&rule.condition, 1)?;
        if depth > self.max_tree_depth {
            return Err(RuleIntegrityError::MaxDepthExceeded {
                depth,
                limit: self.max_tree_depth,
            });
        }

        // 2. Validate all search definitions
        for (search_id, search_def) in &rule.searches {
            if search_def.matchers.is_empty() {
                return Err(RuleIntegrityError::EmptySearchSelection(format!(
                    "Search selection '{}' has no matchers",
                    search_id
                )));
            }

            // Check for contradictory field matchers on the same field
            let mut exact_values_by_field: HashMap<&str, &ValueVariant> = HashMap::new();
            for matcher in &search_def.matchers {
                if matcher.field.is_empty() {
                    return Err(RuleIntegrityError::InvalidFieldMatcher(
                        "Field name cannot be empty".to_string(),
                    ));
                }
                if matcher.values.is_empty() {
                    return Err(RuleIntegrityError::InvalidFieldMatcher(format!(
                        "Field '{}' has no value predicates",
                        matcher.field
                    )));
                }

                // If this is an exact match (no modifiers) with a single value, check if duplicate conflicting match exists
                if matcher.modifiers.is_empty() && matcher.values.len() == 1 {
                    if let Some(existing_val) = exact_values_by_field.get(matcher.field.as_str()) {
                        if *existing_val != &matcher.values[0] {
                            return Err(RuleIntegrityError::ContradictoryCondition(format!(
                                "Field '{}' has contradictory exact match requirements ('{}' vs '{}')",
                                matcher.field, existing_val, matcher.values[0]
                            )));
                        }
                    } else {
                        exact_values_by_field.insert(matcher.field.as_str(), &matcher.values[0]);
                    }
                }
            }
        }

        Ok(())
    }

    fn check_tree_depth(&self, expr: &ConditionExpr, current_depth: usize) -> Result<usize, RuleIntegrityError> {
        if current_depth > self.max_tree_depth {
            return Err(RuleIntegrityError::MaxDepthExceeded {
                depth: current_depth,
                limit: self.max_tree_depth,
            });
        }

        match expr {
            ConditionExpr::SearchRef(_) | ConditionExpr::OneOf(_) | ConditionExpr::AllOf(_) => {
                Ok(current_depth)
            }
            ConditionExpr::Not(inner) => self.check_tree_depth(inner, current_depth + 1),
            ConditionExpr::And(branches) | ConditionExpr::Or(branches) => {
                let mut max_child_depth = current_depth;
                for b in branches {
                    let d = self.check_tree_depth(b, current_depth + 1)?;
                    if d > max_child_depth {
                        max_child_depth = d;
                    }
                }
                Ok(max_child_depth)
            }
        }
    }
}
