use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use crate::types::ValueVariant;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SchemaKey {
    pub event_type: String,
    pub version: u32,
}

impl SchemaKey {
    pub fn new(event_type: impl Into<String>, version: u32) -> Self {
        Self {
            event_type: event_type.into(),
            version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldDataType {
    String,
    Integer,
    Float,
    Boolean,
    Array,
    Object,
    Any,
}

#[derive(Debug, Clone)]
pub struct FieldRule {
    pub field_name: String,
    pub expected_type: FieldDataType,
    pub is_required: bool,
    pub min_int: Option<i64>,
    pub max_int: Option<i64>,
    pub allowed_strings: Option<Vec<String>>,
}

impl FieldRule {
    pub fn required(name: impl Into<String>, expected_type: FieldDataType) -> Self {
        Self {
            field_name: name.into(),
            expected_type,
            is_required: true,
            min_int: None,
            max_int: None,
            allowed_strings: None,
        }
    }

    pub fn optional(name: impl Into<String>, expected_type: FieldDataType) -> Self {
        Self {
            field_name: name.into(),
            expected_type,
            is_required: false,
            min_int: None,
            max_int: None,
            allowed_strings: None,
        }
    }

    pub fn with_range(mut self, min: i64, max: i64) -> Self {
        self.min_int = Some(min);
        self.max_int = Some(max);
        self
    }

    pub fn with_allowed_strings(mut self, allowed: Vec<String>) -> Self {
        self.allowed_strings = Some(allowed);
        self
    }
}

#[derive(Debug, Clone)]
pub struct CompiledSchema {
    pub schema_key: SchemaKey,
    pub fields: HashMap<String, FieldRule>,
    pub strict_additional_fields: bool,
}

impl CompiledSchema {
    pub fn new(schema_key: SchemaKey, strict_additional_fields: bool) -> Self {
        let mut fields = HashMap::new();
        // Standard mandatory fields across all security/detection schemas
        fields.insert(
            "event_id".to_string(),
            FieldRule::required("event_id", FieldDataType::String),
        );
        fields.insert(
            "event_type".to_string(),
            FieldRule::required("event_type", FieldDataType::String),
        );
        fields.insert(
            "timestamp".to_string(),
            FieldRule::required("timestamp", FieldDataType::Any), // can be string, int epoch, float
        );
        fields.insert(
            "source".to_string(),
            FieldRule::required("source", FieldDataType::String),
        );
        fields.insert(
            "entity_id".to_string(),
            FieldRule::required("entity_id", FieldDataType::String),
        );

        Self {
            schema_key,
            fields,
            strict_additional_fields,
        }
    }

    pub fn add_field(&mut self, rule: FieldRule) -> &mut Self {
        self.fields.insert(rule.field_name.clone(), rule);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub schema_key: String,
    pub field_name: String,
    pub error_code: String,
    pub message: String,
    pub raw_snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLQRecord {
    pub raw_payload: String,
    pub failure_timestamp_ns: i64,
    pub error: ValidationError,
}

#[derive(Debug, Default)]
pub struct DeadLetterQueue {
    records: RwLock<Vec<DLQRecord>>,
    total_dlq_count: AtomicU64,
}

impl DeadLetterQueue {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(Vec::new()),
            total_dlq_count: AtomicU64::new(0),
        }
    }

    pub fn push(&self, raw_payload: String, error: ValidationError) {
        self.total_dlq_count.fetch_add(1, Ordering::Relaxed);
        let mut list = self.records.write();
        list.push(DLQRecord {
            raw_payload,
            failure_timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            error,
        });
    }

    pub fn len(&self) -> usize {
        self.records.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.read().is_empty()
    }

    pub fn drain_records(&self) -> Vec<DLQRecord> {
        let mut list = self.records.write();
        std::mem::take(&mut *list)
    }
}

pub struct SchemaValidator {
    schemas: RwLock<HashMap<SchemaKey, CompiledSchema>>,
    dlq: Arc<DeadLetterQueue>,
    total_validated: AtomicU64,
    total_passed: AtomicU64,
    total_failed: AtomicU64,
}

impl SchemaValidator {
    pub fn new(dlq: Arc<DeadLetterQueue>) -> Self {
        Self {
            schemas: RwLock::new(HashMap::new()),
            dlq,
            total_validated: AtomicU64::new(0),
            total_passed: AtomicU64::new(0),
            total_failed: AtomicU64::new(0),
        }
    }

    pub fn register_schema(&self, schema: CompiledSchema) {
        let mut map = self.schemas.write();
        map.insert(schema.schema_key.clone(), schema);
    }

    /// Validates an extracted attributes map against the registered schema
    pub fn validate(
        &self,
        schema_key: &SchemaKey,
        attributes: &HashMap<String, ValueVariant>,
        raw_payload_for_dlq: &[u8],
    ) -> Result<(), ValidationError> {
        self.total_validated.fetch_add(1, Ordering::Relaxed);

        let schemas = self.schemas.read();
        let schema = match schemas.get(schema_key) {
            Some(s) => s,
            None => {
                let err = ValidationError {
                    schema_key: format!("{}:v{}", schema_key.event_type, schema_key.version),
                    field_name: "schema_key".to_string(),
                    error_code: "SCHEMA_NOT_FOUND".to_string(),
                    message: format!("No registered schema for {:?}", schema_key),
                    raw_snippet: None,
                };
                self.record_failure(raw_payload_for_dlq, err.clone());
                return Err(err);
            }
        };

        // 1. Check all required fields are present and match type/constraints
        for (field_name, rule) in &schema.fields {
            match attributes.get(field_name) {
                Some(val) => {
                    if let Err(e) = self.check_field_rule(schema_key, rule, val) {
                        self.record_failure(raw_payload_for_dlq, e.clone());
                        return Err(e);
                    }
                }
                None => {
                    if rule.is_required {
                        let err = ValidationError {
                            schema_key: format!("{}:v{}", schema_key.event_type, schema_key.version),
                            field_name: field_name.clone(),
                            error_code: "MISSING_REQUIRED_FIELD".to_string(),
                            message: format!("Missing required mandatory field '{}'", field_name),
                            raw_snippet: None,
                        };
                        self.record_failure(raw_payload_for_dlq, err.clone());
                        return Err(err);
                    }
                }
            }
        }

        // 2. Strict additional fields check
        if schema.strict_additional_fields {
            for k in attributes.keys() {
                if !schema.fields.contains_key(k) {
                    let err = ValidationError {
                        schema_key: format!("{}:v{}", schema_key.event_type, schema_key.version),
                        field_name: k.clone(),
                        error_code: "UNKNOWN_FIELD_REJECTED".to_string(),
                        message: format!("Unknown field '{}' forbidden under strict schema", k),
                        raw_snippet: None,
                    };
                    self.record_failure(raw_payload_for_dlq, err.clone());
                    return Err(err);
                }
            }
        }

        self.total_passed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn check_field_rule(
        &self,
        schema_key: &SchemaKey,
        rule: &FieldRule,
        val: &ValueVariant,
    ) -> Result<(), ValidationError> {
        let matches_type = match (&rule.expected_type, val) {
            (FieldDataType::Any, _) => true,
            (FieldDataType::String, ValueVariant::String(_)) => true,
            (FieldDataType::Integer, ValueVariant::Int(_)) => true,
            (FieldDataType::Float, ValueVariant::Float(_)) => true,
            (FieldDataType::Float, ValueVariant::Int(_)) => true, // numeric promotion
            (FieldDataType::Boolean, ValueVariant::Bool(_)) => true,
            (FieldDataType::Array, ValueVariant::Array(_)) => true,
            (FieldDataType::Object, ValueVariant::Map(_)) => true,
            _ => false,
        };

        if !matches_type {
            return Err(ValidationError {
                schema_key: format!("{}:v{}", schema_key.event_type, schema_key.version),
                field_name: rule.field_name.clone(),
                error_code: "TYPE_MISMATCH".to_string(),
                message: format!(
                    "Field '{}' expected type {:?}, got {:?}",
                    rule.field_name, rule.expected_type, val
                ),
                raw_snippet: Some(val.to_string()),
            });
        }

        // Range constraint check for integers
        if let ValueVariant::Int(num) = val {
            if let Some(min) = rule.min_int {
                if *num < min {
                    return Err(ValidationError {
                        schema_key: format!("{}:v{}", schema_key.event_type, schema_key.version),
                        field_name: rule.field_name.clone(),
                        error_code: "RANGE_UNDERFLOW".to_string(),
                        message: format!("Field '{}' value {} below minimum {}", rule.field_name, num, min),
                        raw_snippet: Some(num.to_string()),
                    });
                }
            }
            if let Some(max) = rule.max_int {
                if *num > max {
                    return Err(ValidationError {
                        schema_key: format!("{}:v{}", schema_key.event_type, schema_key.version),
                        field_name: rule.field_name.clone(),
                        error_code: "RANGE_OVERFLOW".to_string(),
                        message: format!("Field '{}' value {} exceeds maximum {}", rule.field_name, num, max),
                        raw_snippet: Some(num.to_string()),
                    });
                }
            }
        }

        // Enum string allowed list check
        if let ValueVariant::String(s) = val {
            if let Some(ref allowed) = rule.allowed_strings {
                if !allowed.contains(s) {
                    return Err(ValidationError {
                        schema_key: format!("{}:v{}", schema_key.event_type, schema_key.version),
                        field_name: rule.field_name.clone(),
                        error_code: "ENUM_CONSTRAINT_VIOLATION".to_string(),
                        message: format!("Field '{}' string value '{}' not in allowed list {:?}", rule.field_name, s, allowed),
                        raw_snippet: Some(s.clone()),
                    });
                }
            }
        }

        Ok(())
    }

    fn record_failure(&self, raw_bytes: &[u8], err: ValidationError) {
        self.total_failed.fetch_add(1, Ordering::Relaxed);
        let raw_str = String::from_utf8_lossy(raw_bytes).to_string();
        self.dlq.push(raw_str, err);
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.total_validated.load(Ordering::Relaxed),
            self.total_passed.load(Ordering::Relaxed),
            self.total_failed.load(Ordering::Relaxed),
        )
    }
}
