use std::collections::{HashMap, HashSet};
use std::fmt;
use crate::condition_parser::ConditionParser;
use crate::rule_ast::*;
use crate::sigma_parser::SigmaRuleRaw;
use crate::types::ValueVariant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleValidationErrorKind {
    MissingRequiredField,
    MissingCondition,
    InvalidConditionSyntax,
    UndefinedIdentifier,
    InvalidModifier,
    EmptySearchSelection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleValidationError {
    pub kind: RuleValidationErrorKind,
    pub message: String,
    pub field_context: Option<String>,
}

impl fmt::Display for RuleValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Rule validation error ({:?}): {} [field={:?}]",
            self.kind, self.message, self.field_context
        )
    }
}

impl std::error::Error for RuleValidationError {}

pub struct RuleValidator;

impl RuleValidator {
    /// Validates raw Sigma rule syntax and semantics, compiling into a strongly typed RuleAST
    pub fn compile_and_validate(raw: &SigmaRuleRaw) -> Result<RuleAST, RuleValidationError> {
        // 1. Mandatory metadata checks
        if raw.title.trim().is_empty() {
            return Err(RuleValidationError {
                kind: RuleValidationErrorKind::MissingRequiredField,
                message: "Rule title cannot be empty".to_string(),
                field_context: Some("title".to_string()),
            });
        }

        // 2. Extract and parse condition
        let condition_val = raw.detection.get("condition").ok_or_else(|| RuleValidationError {
            kind: RuleValidationErrorKind::MissingCondition,
            message: "Missing mandatory 'condition' field in detection block".to_string(),
            field_context: Some("detection.condition".to_string()),
        })?;

        let condition_str = match condition_val {
            serde_yaml::Value::String(s) => s.as_str(),
            _ => {
                return Err(RuleValidationError {
                    kind: RuleValidationErrorKind::InvalidConditionSyntax,
                    message: "Condition must be a string".to_string(),
                    field_context: Some("detection.condition".to_string()),
                })
            }
        };

        let condition_ast = ConditionParser::parse(condition_str).map_err(|e| RuleValidationError {
            kind: RuleValidationErrorKind::InvalidConditionSyntax,
            message: format!("Condition parse failure: {}", e),
            field_context: Some("detection.condition".to_string()),
        })?;

        // 3. Extract all defined search selections (excluding 'condition')
        let mut searches = HashMap::new();
        let mut defined_identifiers = HashSet::new();

        for (key, val) in &raw.detection {
            if key == "condition" || key == "timeframe" {
                continue;
            }
            defined_identifiers.insert(key.clone());
            let selection = Self::parse_search_selection(key, val)?;
            searches.insert(key.clone(), selection);
        }

        if searches.is_empty() {
            return Err(RuleValidationError {
                kind: RuleValidationErrorKind::EmptySearchSelection,
                message: "Detection block must define at least one search identifier".to_string(),
                field_context: Some("detection".to_string()),
            });
        }

        // 4. Semantic check: verify all identifiers referenced in ConditionExpr exist
        Self::verify_condition_identifiers(&condition_ast, &defined_identifiers)?;

        // 5. Construct final strongly typed RuleAST
        let logsource = LogsourceNode {
            category: raw.logsource.category.clone(),
            product: raw.logsource.product.clone(),
            service: raw.logsource.service.clone(),
            definition: raw.logsource.definition.clone(),
        };

        let level = raw
            .level
            .as_deref()
            .map(RuleLevel::from_str)
            .unwrap_or(RuleLevel::Medium);

        Ok(RuleAST {
            id: raw.id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            title: raw.title.clone(),
            level,
            logsource,
            searches,
            condition: condition_ast,
            tags: raw.tags.clone().unwrap_or_default(),
        })
    }

    fn parse_search_selection(
        identifier: &str,
        val: &serde_yaml::Value,
    ) -> Result<SearchSelection, RuleValidationError> {
        let mut matchers = Vec::new();

        match val {
            serde_yaml::Value::Mapping(map) => {
                for (k, v) in map {
                    let field_key = match k {
                        serde_yaml::Value::String(s) => s.as_str(),
                        _ => continue,
                    };

                    let (field_name, modifiers) = Self::parse_field_and_modifiers(field_key)?;
                    let values = Self::extract_yaml_values(v)?;

                    matchers.push(FieldMatcher {
                        field: field_name,
                        modifiers,
                        values,
                    });
                }
            }
            serde_yaml::Value::Sequence(seq) => {
                // Anonymous multi-field or keyword search
                let mut values = Vec::new();
                for item in seq {
                    if let Ok(v) = Self::yaml_val_to_variant(item) {
                        values.push(v);
                    }
                }
                matchers.push(FieldMatcher {
                    field: "*".to_string(), // Wildcard keyword search
                    modifiers: vec![ModifierType::Contains],
                    values,
                });
            }
            serde_yaml::Value::String(s) => {
                matchers.push(FieldMatcher {
                    field: "*".to_string(),
                    modifiers: vec![ModifierType::Contains],
                    values: vec![ValueVariant::String(s.clone())],
                });
            }
            _ => {}
        }

        Ok(SearchSelection {
            identifier: identifier.to_string(),
            matchers,
            is_negative: false,
        })
    }

    fn parse_field_and_modifiers(raw_field: &str) -> Result<(String, Vec<ModifierType>), RuleValidationError> {
        let parts: Vec<&str> = raw_field.split('|').collect();
        let field_name = parts[0].to_string();
        let mut modifiers = Vec::new();

        for m_str in &parts[1..] {
            if let Some(m) = ModifierType::from_str(m_str) {
                modifiers.push(m);
            } else {
                return Err(RuleValidationError {
                    kind: RuleValidationErrorKind::InvalidModifier,
                    message: format!("Unknown or invalid modifier '|{}' on field '{}'", m_str, field_name),
                    field_context: Some(raw_field.to_string()),
                });
            }
        }

        if modifiers.is_empty() {
            modifiers.push(ModifierType::Exact);
        }

        Ok((field_name, modifiers))
    }

    fn extract_yaml_values(val: &serde_yaml::Value) -> Result<Vec<ValueVariant>, RuleValidationError> {
        let mut out = Vec::new();
        match val {
            serde_yaml::Value::Sequence(seq) => {
                for item in seq {
                    out.push(Self::yaml_val_to_variant(item)?);
                }
            }
            _ => {
                out.push(Self::yaml_val_to_variant(val)?);
            }
        }
        Ok(out)
    }

    fn yaml_val_to_variant(val: &serde_yaml::Value) -> Result<ValueVariant, RuleValidationError> {
        match val {
            serde_yaml::Value::Null => Ok(ValueVariant::Null),
            serde_yaml::Value::Bool(b) => Ok(ValueVariant::Bool(*b)),
            serde_yaml::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(ValueVariant::Int(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(ValueVariant::Float(f))
                } else {
                    Ok(ValueVariant::Int(0))
                }
            }
            serde_yaml::Value::String(s) => Ok(ValueVariant::String(s.clone())),
            _ => Ok(ValueVariant::String(format!("{:?}", val))),
        }
    }

    fn verify_condition_identifiers(
        expr: &ConditionExpr,
        defined: &HashSet<String>,
    ) -> Result<(), RuleValidationError> {
        match expr {
            ConditionExpr::SearchRef(id) => {
                if !defined.contains(id) {
                    return Err(RuleValidationError {
                        kind: RuleValidationErrorKind::UndefinedIdentifier,
                        message: format!("Condition references undefined search identifier '{}'", id),
                        field_context: Some(format!("detection.condition: {}", id)),
                    });
                }
                Ok(())
            }
            ConditionExpr::OneOf(pat) | ConditionExpr::AllOf(pat) => {
                // If pattern is "them", requires at least 1 defined search
                if pat == "them" {
                    if defined.is_empty() {
                        return Err(RuleValidationError {
                            kind: RuleValidationErrorKind::UndefinedIdentifier,
                            message: "Quantifier '1 of them' used with no search identifiers".to_string(),
                            field_context: None,
                        });
                    }
                    return Ok(());
                }

                // If pattern contains wildcard (e.g. selection_* or filter_*)
                let prefix = pat.trim_end_matches('*');
                let matches_any = defined.iter().any(|d| d.starts_with(prefix));
                if !matches_any {
                    return Err(RuleValidationError {
                        kind: RuleValidationErrorKind::UndefinedIdentifier,
                        message: format!("Quantifier pattern '{}' matches zero defined search identifiers", pat),
                        field_context: Some(pat.clone()),
                    });
                }
                Ok(())
            }
            ConditionExpr::Not(inner) => Self::verify_condition_identifiers(inner, defined),
            ConditionExpr::And(list) | ConditionExpr::Or(list) => {
                for item in list {
                    Self::verify_condition_identifiers(item, defined)?;
                }
                Ok(())
            }
        }
    }
}
