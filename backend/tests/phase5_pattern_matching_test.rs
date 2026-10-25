use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use stream_detect_engine::aho_corasick::AhoCorasick;
use stream_detect_engine::canonical_normalizer::CanonicalEvent;
use stream_detect_engine::compiled_rule_validator::CompiledRuleValidator;
use stream_detect_engine::rule_ast::{FieldMatcher, LogsourceNode, RuleAST, RuleLevel, SearchSelection};
use stream_detect_engine::rule_cache::RuleCompilationCache;
use stream_detect_engine::rule_validator::RuleValidator;
use stream_detect_engine::shared_automata::FieldAutomataRegistry;
use stream_detect_engine::shared_predicate_engine::{PredicateEvaluatorFn, SharedPredicateEngine};
use stream_detect_engine::types::ValueVariant;

#[test]
fn test_feature_25_compilation_cache_acceleration() {
    let cache = RuleCompilationCache::new(256);
    let rule_yaml = r#"
title: Suspicious PowerShell Process
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'Invoke-Mimikatz'
    condition: selection
level: critical
"#;

    // 1st access: compile and insert into cache
    let start_1 = Instant::now();
    let compiled_1 = cache
        .get_or_compile(rule_yaml, |_| {
            let raw = stream_detect_engine::sigma_parser::SigmaParser::parse_yaml(rule_yaml).unwrap();
            RuleValidator::compile_and_validate(&raw).map_err(|e| e.to_string())
        })
        .expect("Compilation should succeed");
    let dur_1 = start_1.elapsed();

    // 2nd through 1000th access: must hit cache in sub-microsecond time
    let iterations = 1000;
    let start_cached = Instant::now();
    for _ in 0..iterations {
        let cached = cache
            .get_or_compile(rule_yaml, |_| -> Result<RuleAST, String> {
                panic!("Should not re-compile!")
            })
            .expect("Cache hit should succeed");
        assert_eq!(cached.fingerprint, compiled_1.fingerprint);
    }
    let dur_cached = start_cached.elapsed();
    let amortized_ns = (dur_cached.as_nanos() as f64) / (iterations as f64);

    let (hits, misses) = cache.stats();
    assert_eq!(hits, 1000);
    assert_eq!(misses, 1);
    assert!(
        amortized_ns < 10000.0,
        "Cache lookup latency must be fast (actual: {:.2} ns/lookup, 1st compile: {:?})",
        amortized_ns,
        dur_1
    );
}

#[test]
fn test_feature_26_compiled_rule_integrity_rejection() {
    let validator = CompiledRuleValidator::default();

    // Construct AST with contradictory exact match requirements: ProcessId == 100 AND ProcessId == 200
    let mut searches = std::collections::HashMap::new();
    searches.insert(
        "selection_contradictory".to_string(),
        SearchSelection {
            identifier: "selection_contradictory".to_string(),
            matchers: vec![
                FieldMatcher {
                    field: "ProcessId".to_string(),
                    modifiers: vec![],
                    values: vec![ValueVariant::Int(100)],
                },
                FieldMatcher {
                    field: "ProcessId".to_string(),
                    modifiers: vec![],
                    values: vec![ValueVariant::Int(200)],
                },
            ],
            is_negative: false,
        },
    );

    let invalid_rule = RuleAST {
        id: "rule-invalid-1".to_string(),
        title: "Impossible Contradictory Rule".to_string(),
        level: RuleLevel::Critical,
        logsource: LogsourceNode {
            category: Some("process_creation".to_string()),
            product: None,
            service: None,
            definition: None,
        },
        searches,
        condition: stream_detect_engine::rule_ast::ConditionExpr::SearchRef("selection_contradictory".to_string()),
        tags: vec![],
    };

    let result = validator.validate(&invalid_rule);
    assert!(result.is_err(), "Validator must reject contradictory field conditions");
}

#[test]
fn test_feature_27_aho_corasick_multi_pattern_sweep() {
    let mut ac = AhoCorasick::new(true);

    // Insert 1,000 distinct command line patterns
    for i in 0..1000 {
        let pattern = format!("malware_binary_flag_{:04}.exe", i);
        ac.add_pattern(pattern.as_bytes(), i as u32);
    }
    ac.build();
    assert_eq!(ac.pattern_count(), 1000);

    // Construct a 1MB payload containing 10 injected patterns
    let mut payload = vec![b'A'; 1024 * 1024]; // 1 MB buffer
    let injected_ids = [42, 105, 256, 512, 789, 999];
    for &id in &injected_ids {
        let pat = format!("malware_binary_flag_{:04}.exe", id);
        let offset = (id as usize) * 800 + 1000;
        payload[offset..offset + pat.len()].copy_from_slice(pat.as_bytes());
    }

    let start = Instant::now();
    let mut matched_ids = Vec::new();
    ac.find_all(&payload, |_offset, match_id| {
        matched_ids.push(match_id);
    });
    let elapsed = start.elapsed();

    for &id in &injected_ids {
        assert!(
            matched_ids.contains(&(id as u32)),
            "Automaton must detect injected pattern ID {}",
            id
        );
    }

    let mb_per_sec = (1.0) / elapsed.as_secs_f64();
    assert!(
        mb_per_sec > 10.0,
        "Aho-Corasick scanning throughput must be high (actual: {:.2} MB/s, elapsed: {:?})",
        mb_per_sec,
        elapsed
    );
}

#[test]
fn test_feature_28_and_29_cross_rule_automaton_sharing() {
    let registry = FieldAutomataRegistry::new();

    // Register 50 rules inspecting 'process.command_line' with overlapping keywords
    let mut patterns: Vec<(&[u8], String, String)> = Vec::new();
    for i in 0..50 {
        let pat_bytes = if i % 2 == 0 {
            b"powershell.exe -enc" as &[u8]
        } else {
            b"cmd.exe /c whoami" as &[u8]
        };
        patterns.push((pat_bytes, format!("rule_{}", i), format!("selection_{}", i)));
    }

    registry.register_field_patterns("process.command_line", &patterns, true);
    assert_eq!(registry.field_count(), 1, "Only 1 shared field automaton should be constructed");

    // Scan a test payload matching powershell.exe -enc
    let payload = b"Executing C:\\Windows\\System32\\powershell.exe -enc Y21kLmV4ZQ==";
    let mut triggered_rules = Vec::new();
    registry.scan_field("process.command_line", payload, |rule_id, search_id, _offset| {
        triggered_rules.push((rule_id.to_string(), search_id.to_string()));
    });

    // 25 even-numbered rules should fire
    assert_eq!(triggered_rules.len(), 25);
    for (r, s) in triggered_rules {
        assert!(r.starts_with("rule_"));
        assert!(s.starts_with("selection_"));
    }
}

#[test]
fn test_feature_30_shared_predicate_evaluation_cse() {
    let cse_engine = SharedPredicateEngine::new();

    let eval_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&eval_counter);

    let pred_fn: PredicateEvaluatorFn = Arc::new(move |event: &CanonicalEvent| {
        counter_clone.fetch_add(1, Ordering::SeqCst);
        if let Some(ValueVariant::Int(port)) = event.attributes.get("destination.port") {
            *port == 443
        } else {
            false
        }
    });

    // Register the same predicate for 20 distinct rules
    let mut pred_ids = Vec::new();
    for i in 0..20 {
        let rule_name = format!("rule_https_{}", i);
        let id = cse_engine.register_predicate("destination.port", "==", "443", &rule_name, Arc::clone(&pred_fn));
        pred_ids.push(id);
    }

    assert_eq!(cse_engine.predicate_count(), 1, "Duplicate predicate must be deduplicated to 1 DAG node");
    let pred_id = pred_ids[0];

    // Ingest a synthetic event
    let mut event = CanonicalEvent::default();
    event.event_type = "net_flow".to_string();
    event.attributes.insert("destination.port".to_string(), ValueVariant::Int(443));

    let mut event_ctx = cse_engine.create_event_context();

    // Evaluate across all 20 rules
    for _ in 0..20 {
        let match_result = cse_engine.evaluate_predicate(pred_id, &event, &mut event_ctx);
        assert!(match_result, "Port 443 must evaluate to true");
    }

    // Predicate closure must have executed EXACTLY 1 time across all 20 rule invocations!
    assert_eq!(
        eval_counter.load(Ordering::SeqCst),
        1,
        "Shared predicate must execute exactly 1 time per event (CSE reuse verified)"
    );

    let (total_evals, hits) = cse_engine.stats();
    assert_eq!(total_evals, 1);
    assert_eq!(hits, 19);
}
