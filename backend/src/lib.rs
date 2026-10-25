pub mod types;
pub mod kafka_consumer;
pub mod batch_ingress;
pub mod single_ingress;
pub mod schema_validator;
pub mod json_decoder;
pub mod canonical_normalizer;

// Phase II Modules
pub mod zero_copy_buffer;
pub mod timestamp_extractor;
pub mod dedup_key_generator;
pub mod metadata_enricher;
pub mod affinity_router;
pub mod ingress_metrics;

// Phase III Modules (Sigma DSL & Compiler Core)
pub mod quarantine_dlq;
pub mod sigma_parser;
pub mod rule_ast;
pub mod condition_parser;
pub mod field_resolver;
pub mod rule_validator;

// Phase IV Modules (DSL & Evaluation Operators)
pub mod boolean_evaluator;
pub mod string_operators;
pub mod numeric_evaluator;
pub mod regex_engine;
pub mod set_membership;
pub mod glob_matcher;

// Phase V Modules (Automata & Common Subexpression Engine)
pub mod rule_cache;
pub mod compiled_rule_validator;
pub mod aho_corasick;
pub mod shared_automata;
pub mod shared_predicate_engine;

// Phase VI Modules (Text Processing, Perfect Hashing & Cost Optimizations)
pub mod case_folding;
pub mod token_index;
pub mod exact_matcher;
pub mod regex_guard;
pub mod cost_evaluator;

// Phase VII Modules (Predicate Telemetry & Windows / Event Time Core)
pub mod predicate_telemetry;
pub mod hit_telemetry;
pub mod matcher_benchmark;
pub mod sliding_window;
pub mod tumbling_window;
pub mod session_window;

// Phase VIII Modules (Event-Time Semantics & Watermark Architecture)
pub mod event_time_driver;
pub mod processing_time_fallback;
pub mod watermark_generator;
pub mod partition_watermark_tracker;
pub mod event_reorderer;
pub mod lateness_policy;

// Phase IX Modules (State Management, Window GC & Keyed Store Core)
pub mod late_event_policy;
pub mod window_gc;
pub mod window_memory_tracker;
pub mod window_oracle;
pub mod keyed_state_store;
pub mod composite_key;

// Phase X Modules (State Durability, TTL & Deduplication Core)
pub mod timing_wheel;
pub mod idle_eviction;
pub mod state_limiter;
pub mod state_snapshot;
pub mod state_restore;
pub mod dedup_engine;

// Phase XI Modules (State TTL Conclusion & Alerting / Detection Lifecycle)
pub mod detection_match;
pub mod alert_dedup;
pub mod dedup_wheel;
pub mod idempotent_committer;
pub mod state_telemetry;
pub mod state_recovery_test;

use std::sync::Arc;
use crate::kafka_consumer::*;
use crate::batch_ingress::*;
use crate::single_ingress::*;
use crate::schema_validator::*;
use crate::json_decoder::*;
use crate::canonical_normalizer::*;
use crate::zero_copy_buffer::*;
use crate::timestamp_extractor::*;
use crate::dedup_key_generator::*;
use crate::metadata_enricher::*;
use crate::affinity_router::*;
use crate::ingress_metrics::*;
use crate::quarantine_dlq::*;
use crate::field_resolver::*;

/// Unified Stream Detection Engine orchestrating Phases I, II & III
pub struct StreamDetectionIngressEngine {
    pub kafka_consumer: Arc<KafkaStreamConsumer>,
    pub batch_controller: Arc<BatchIngressController>,
    pub single_ingress: Arc<SingleEventIngressHandler>,
    pub schema_validator: Arc<SchemaValidator>,
    pub dlq: Arc<DeadLetterQueue>,
    pub normalizer: Arc<CanonicalNormalizer>,
    pub memory_arena: Arc<MemoryArena>,
    pub timestamp_extractor: Arc<TimestampExtractor>,
    pub uuid_gen: Arc<UUIDv7Generator>,
    pub metadata_enricher: Arc<MetadataEnricher>,
    pub affinity_router: Arc<PartitionRouter>,
    pub metrics: Arc<IngressMetricsRegistry>,
    pub quarantine: Arc<QuarantineManager>,
    pub field_resolver: Arc<FieldResolver>,
}

impl StreamDetectionIngressEngine {
    pub fn new(
        consumer_config: ConsumerConfig,
        broker: Arc<MockKafkaBroker>,
        worker_threads: usize,
        queue_capacity: usize,
    ) -> Self {
        let dlq = Arc::new(DeadLetterQueue::new());
        let validator = Arc::new(SchemaValidator::new(Arc::clone(&dlq)));
        let normalizer = Arc::new(CanonicalNormalizer::new(queue_capacity * 2));
        let single_ingress = Arc::new(SingleEventIngressHandler::new(queue_capacity));
        let memory_arena = Arc::new(MemoryArena::new(32, DEFAULT_PAGE_SIZE));
        let timestamp_extractor = Arc::new(TimestampExtractor::default_extractor());
        let uuid_gen = Arc::new(UUIDv7Generator::new());
        let metadata_enricher = Arc::new(MetadataEnricher::new(SourceProvenance::default()));
        let metrics = Arc::new(IngressMetricsRegistry::new());
        let quarantine = Arc::new(QuarantineManager::new(queue_capacity * 4));
        let field_resolver = Arc::new(FieldResolver::new());

        let norm_clone = Arc::clone(&normalizer);
        let val_clone = Arc::clone(&validator);

        let processor = Arc::new(move |raw_bytes: Vec<u8>| {
            if let Ok(parsed) = SIMDJsonDecoder::decode(&raw_bytes) {
                let schema_key = SchemaKey::new(
                    parsed.get_string("event_type").unwrap_or("generic"),
                    1,
                );
                if val_clone.validate(&schema_key, &parsed.fields, &raw_bytes).is_ok() {
                    let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
                    let _ = norm_clone.normalize(1, now_ns, parsed.fields);
                }
            }
        });

        let batch_controller = Arc::new(BatchIngressController::new(
            worker_threads,
            queue_capacity,
            processor,
        ));

        let kafka_consumer = Arc::new(KafkaStreamConsumer::new(
            consumer_config,
            broker,
            None,
        ));

        let router_consumer = Arc::new(|_partition: usize, _evt: CanonicalEvent| {
            // Downstream detection engine pipeline consumer hook
        });

        let affinity_router = Arc::new(PartitionRouter::new(
            worker_threads,
            queue_capacity,
            router_consumer,
        ));

        Self {
            kafka_consumer,
            batch_controller,
            single_ingress,
            schema_validator: validator,
            dlq,
            normalizer,
            memory_arena,
            timestamp_extractor,
            uuid_gen,
            metadata_enricher,
            affinity_router,
            metrics,
            quarantine,
            field_resolver,
        }
    }
}
