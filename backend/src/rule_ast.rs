use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::types::ValueVariant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleLevel {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl RuleLevel {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "informational" | "info" => Self::Informational,
            "low" => Self::Low,
            "medium" | "med" => Self::Medium,
            "high" => Self::High,
            "critical" | "crit" => Self::Critical,
            _ => Self::Medium,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogsourceNode {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
    pub definition: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModifierType {
    Exact,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    Base64,
    All,
    Cidr,
    GreaterThan,
    LessThan,
}

impl ModifierType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "exact" => Some(Self::Exact),
            "contains" => Some(Self::Contains),
            "startswith" => Some(Self::StartsWith),
            "endswith" => Some(Self::EndsWith),
            "re" | "regex" => Some(Self::Regex),
            "base64" => Some(Self::Base64),
            "all" => Some(Self::All),
            "cidr" => Some(Self::Cidr),
            "gt" => Some(Self::GreaterThan),
            "lt" => Some(Self::LessThan),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldMatcher {
    pub field: String,
    pub modifiers: Vec<ModifierType>,
    pub values: Vec<ValueVariant>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchSelection {
    pub identifier: String,
    pub matchers: Vec<FieldMatcher>,
    pub is_negative: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConditionExpr {
    SearchRef(String),
    OneOf(String),       // e.g. "1 of selection_*" or "1 of them"
    AllOf(String),       // e.g. "all of selection_*" or "all of them"
    Not(Box<ConditionExpr>),
    And(Vec<ConditionExpr>),
    Or(Vec<ConditionExpr>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleAST {
    pub id: String,
    pub title: String,
    pub level: RuleLevel,
    pub logsource: LogsourceNode,
    pub searches: HashMap<String, SearchSelection>,
    pub condition: ConditionExpr,
    pub tags: Vec<String>,
}
