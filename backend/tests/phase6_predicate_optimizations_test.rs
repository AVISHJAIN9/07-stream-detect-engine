use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use stream_detect_engine::case_folding::CaseNormalizer;
use stream_detect_engine::cost_evaluator::{CostTier, InstrumentedPredicate, ShortCircuitEngine};
use stream_detect_engine::exact_matcher::ExactMatchAccelerator;
use stream_detect_engine::regex_guard::{GuardedRegexMatcher, RegexGuardError};
use stream_detect_engine::token_index::InvertedRuleIndex;

#[test]
fn test_feature_31_simd_ascii_case_normalization_speed() {
    let size = 10 * 1024 * 1024; // 10 MB
    let mut buffer = vec![b'A'; size];

    // Interleave mixed uppercase / lowercase / punctuation
    for i in 0..size {
        buffer[i] = match i % 4 {
            0 => b'A' + ((i % 26) as u8),
            1 => b'a' + ((i % 26) as u8),
            2 => b'0' + ((i % 10) as u8),
            _ => b'_',
        };
    }

    let start = Instant::now();
    CaseNormalizer::normalize_ascii_in_place(&mut buffer);
    let elapsed = start.elapsed();

    // Verify all uppercase characters converted
    assert!(!CaseNormalizer::has_ascii_uppercase(&buffer));

    let gb_per_sec = (10.0 / 1024.0) / elapsed.as_secs_f64();
    println!("  - SIMD In-Place Lowercasing: 10 MB in {:.2}ms ({:.2} GB/s)", elapsed.as_secs_f64() * 1000.0, gb_per_sec);
    assert!(
        elapsed.as_millis() < 500,
        "Vectorized in-place lowercasing must complete rapidly (actual: {:?})",
        elapsed
    );
}

#[test]
fn test_feature_32_unicode_full_case_folding_and_homoglyphs() {
    // German Straße / STRAßE full folding -> strasse
    let german_upper = "STRAßE";
    let german_folded = CaseNormalizer::to_lowercase_unicode(german_upper);
    assert_eq!(german_folded, "strasse", "German uppercase ß must expand to 'ss'");

    // Greek capital Sigma Σ folding
    let greek_sigma = "ΣΥΣΤΗΜΑ";
    let greek_folded = CaseNormalizer::to_lowercase_unicode(greek_sigma);
    assert!(greek_folded.starts_with('σ'));

    // Mixed multilingual string
    let mixed = "C:\\Windows\\System32\\MÜLL.EXE";
    let mixed_folded = CaseNormalizer::to_lowercase_unicode(mixed);
    assert_eq!(mixed_folded, "c:\\windows\\system32\\müll.exe");
}

#[test]
fn test_feature_33_token_inverted_index_candidate_pruning() {
    let index = InvertedRuleIndex::new();

    // Register 1,000 rules with distinct benign tokens
    for i in 0..1000 {
        let tokens = [format!("service_{:04}", i), "windows".to_string(), "system".to_string()];
        let token_refs: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();
        index.register_rule(i as u32, &token_refs);
    }

    // Register 5 targeted rules for "mimikatz"
    for i in 1000..1005 {
        index.register_rule(i as u32, &["mimikatz", "sekurlsa", "lsass"]);
    }

    // Query event with mimikatz
    let event_cmd = "powershell.exe -c Invoke-Mimikatz -DumpCreds";
    let candidates = index.query_candidates(event_cmd);
    let matched_rules = candidates.to_vec();

    // Verify candidate pruning: exactly the 5 target rules returned, 1,000 pruned (> 99% pruning!)
    assert_eq!(matched_rules.len(), 5);
    for r in matched_rules {
        assert!(r >= 1000 && r < 1005);
    }
}

#[test]
fn test_feature_34_exact_match_acceleration_latency() {
    let accelerator = ExactMatchAccelerator::new();

    for i in 0..5000 {
        let val = format!("binary_{:05}.exe", i);
        accelerator.register("process.name", &val, i as u32, true);
    }
    accelerator.register("process.name", "powershell.exe", 9999, true);

    let start = Instant::now();
    let iterations = 10_000;
    let mut results = Vec::with_capacity(8);

    for _ in 0..iterations {
        results.clear();
        accelerator.lookup("process.name", "powershell.exe", &mut results);
        assert!(!results.is_empty());
    }
    let elapsed = start.elapsed();
    let amortized_ns = (elapsed.as_nanos() as f64) / (iterations as f64);

    assert!(
        amortized_ns < 2000.0,
        "Exact match point lookup must be ultra fast (actual: {:.2} ns/lookup)",
        amortized_ns
    );
}

#[test]
fn test_feature_35_regex_fuel_guardrail_protection() {
    // Pathological regex: (a+)+$
    let matcher = GuardedRegexMatcher::compile(r"(a+)+$", false, 1000)
        .expect("Compilation should succeed");

    // Attack payload exceeding fuel budget (5,000 bytes)
    let attack_payload = format!("{}b", "a".repeat(5000));
    let result = matcher.match_with_fuel(attack_payload.as_bytes(), 1000);

    match result {
        Err(RegexGuardError::FuelExhausted { attempted_bytes, fuel_budget }) => {
            assert_eq!(attempted_bytes, 5001);
            assert_eq!(fuel_budget, 1000);
        }
        _ => panic!("Expected FuelExhausted error on payload exceeding fuel limit"),
    }

    assert_eq!(matcher.throttled_count(), 1);
}

#[test]
fn test_feature_36_adaptive_predicate_short_circuiting() {
    let regex_counter = Arc::new(AtomicUsize::new(0));
    let regex_counter_clone = Arc::clone(&regex_counter);

    let exact_pred = InstrumentedPredicate::new(
        1,
        "Exact: EventID == 4688",
        CostTier::Tier0ExactHash,
        Arc::new(|val: &i64| *val == 4688),
    );

    let regex_pred = InstrumentedPredicate::new(
        2,
        "Regex: CommandLine match",
        CostTier::Tier3RegexDFA,
        Arc::new(move |_val: &i64| {
            regex_counter_clone.fetch_add(1, Ordering::SeqCst);
            true
        }),
    );

    let mut engine = ShortCircuitEngine::new(vec![regex_pred, exact_pred]);

    // Rank predicates: Exact match (Cost = 1) must be sorted BEFORE Regex (Cost = 500)
    engine.rank_predicates();

    let mut eval_order = Vec::new();
    // Ingest non-matching event (EventID = 1)
    let non_matching_event = 1i64;
    let matched = engine.evaluate_and(&non_matching_event, &mut eval_order);

    assert!(!matched, "Non-matching event must return false");
    // Verify execution order: Exact match (ID 1) was tested first
    assert_eq!(eval_order, vec![1]);
    // Expensive regex was NEVER evaluated due to early short-circuiting!
    assert_eq!(regex_counter.load(Ordering::SeqCst), 0);
}
