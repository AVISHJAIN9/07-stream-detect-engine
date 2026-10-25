use std::collections::HashMap;
use std::fmt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogsourceRaw {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
    pub definition: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigmaRuleRaw {
    pub title: String,
    pub id: Option<String>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub references: Option<Vec<String>>,
    pub logsource: LogsourceRaw,
    pub detection: HashMap<String, serde_yaml::Value>,
    pub fields: Option<Vec<String>>,
    pub falsepositives: Option<Vec<String>>,
    pub level: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct SigmaParseError {
    pub message: String,
}

impl fmt::Display for SigmaParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sigma YAML parse error: {}", self.message)
    }
}

impl std::error::Error for SigmaParseError {}

pub struct SigmaParser;

impl SigmaParser {
    /// Parses a single Sigma YAML rule document
    pub fn parse_yaml(yaml_content: &str) -> Result<SigmaRuleRaw, SigmaParseError> {
        serde_yaml::from_str::<SigmaRuleRaw>(yaml_content).map_err(|e| SigmaParseError {
            message: format!("Failed to deserialize Sigma rule: {}", e),
        })
    }

    /// Parses multi-document YAML streams separated by '---'
    pub fn parse_multi_document_yaml(yaml_content: &str) -> Result<Vec<SigmaRuleRaw>, SigmaParseError> {
        let mut rules = Vec::new();
        for doc in serde_yaml::Deserializer::from_str(yaml_content) {
            let rule = SigmaRuleRaw::deserialize(doc).map_err(|e| SigmaParseError {
                message: format!("Failed to parse YAML document in multi-doc stream: {}", e),
            })?;
            rules.push(rule);
        }
        Ok(rules)
    }
}
