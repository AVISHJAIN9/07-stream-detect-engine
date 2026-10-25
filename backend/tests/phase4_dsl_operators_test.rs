use std::time::Instant;
use stream_detect_engine::boolean_evaluator::{BooleanEvaluator, MapSearchContext};
use stream_detect_engine::glob_matcher::GlobMatcher;
use stream_detect_engine::numeric_evaluator::{NumericOp, NumericPredicate};
use stream_detect_engine::regex_engine::SafeRegexMatcher;
use stream_detect_engine::rule_ast::ConditionExpr;
use stream_detect_engine::set_membership::SetEvaluator;
use stream_detect_engine::string_operators::{Base64OffsetCompiler, StringOperatorEvaluator};
use stream_detect_engine::types::ValueVariant;

#[test]
fn test_feature_19_boolean_short_circuiting() {
    // Construct AST: selection_cheap AND selection_expensive
    let ast = ConditionExpr::And(vec![
        ConditionExpr::SearchRef("selection_cheap".to_string()),
        ConditionExpr::SearchRef("selection_expensive".to_string()),
    ]);

    let mut ctx = MapSearchContext::new()
        .with_result("selection_cheap", false)
        .with_result("selection_expensive", true);

    // Evaluate
    let result = BooleanEvaluator::evaluate(&ast, &mut ctx);
    assert!(!result, "AND condition with first false branch must evaluate to false");

    // Verify short-circuiting: selection_expensive was NEVER called
    assert_eq!(ctx.evaluation_counts.get("selection_cheap"), Some(&1));
    assert_eq!(
        ctx.evaluation_counts.get("selection_expensive"),
        None,
        "Expensive branch must not be evaluated when first branch short-circuits"
    );

    // Test OR short-circuiting
    let ast_or = ConditionExpr::Or(vec![
        ConditionExpr::SearchRef("selection_quick_true".to_string()),
        ConditionExpr::SearchRef("selection_expensive_never".to_string()),
    ]);
    let mut ctx_or = MapSearchContext::new()
        .with_result("selection_quick_true", true)
        .with_result("selection_expensive_never", false);

    let result_or = BooleanEvaluator::evaluate(&ast_or, &mut ctx_or);
    assert!(result_or, "OR condition with first true branch must evaluate to true");
    assert_eq!(ctx_or.evaluation_counts.get("selection_quick_true"), Some(&1));
    assert_eq!(
        ctx_or.evaluation_counts.get("selection_expensive_never"),
        None,
        "Second branch in OR must not be evaluated when first branch is true"
    );
}

#[test]
fn test_feature_20_string_modifiers_and_base64_offset_matching() {
    let target = "cmd.exe";
    let variations = Base64OffsetCompiler::generate_base64_variations(target);
    assert_eq!(variations.len(), 3, "Must generate 3 base64 offset variations for 3-byte alignment");

    // Simulate 3 raw unaligned command line payloads containing base64 data
    // Case 0: aligned at byte 0
    let payload_offset0 = "powershell -e Y21kLmV4ZQ=="; // "cmd.exe"
    // Case 1: aligned at byte 1 (e.g. prefix "a") -> "acmd.exe" = "YWNtZC5leGU="
    let payload_offset1 = "powershell -enc YWNtZC5leGU=";
    // Case 2: aligned at byte 2 (e.g. prefix "ab") -> "abcmd.exe" = "YWJjbWQuZXhl"
    let payload_offset2 = "powershell -enc YWJjbWQuZXhl";

    // Verify at least one generated variation matches each unaligned payload without decoding
    let match0 = variations.iter().any(|v| payload_offset0.contains(v));
    let match1 = variations.iter().any(|v| payload_offset1.contains(v));
    let match2 = variations.iter().any(|v| payload_offset2.contains(v));

    assert!(match0, "Offset 0 variation must match byte 0 aligned payload");
    assert!(match1, "Offset 1 variation must match byte 1 aligned payload");
    assert!(match2, "Offset 2 variation must match byte 2 aligned payload");

    // Test StringOperatorEvaluator case-insensitive methods
    let sample = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    assert!(StringOperatorEvaluator::match_contains(sample, "System32", true));
    assert!(StringOperatorEvaluator::match_startswith(sample, "c:\\windows", true));
    assert!(StringOperatorEvaluator::match_endswith(sample, ".EXE", true));
    assert!(!StringOperatorEvaluator::match_endswith(sample, ".dll", true));
}

#[test]
fn test_feature_21_coercion_and_numeric_range_evaluation() {
    let between_pred = NumericPredicate::new(NumericOp::Between(8000.0, 8443.0));

    // Integer in range
    assert!(between_pred.evaluate(&ValueVariant::Int(8080)));
    assert!(between_pred.evaluate(&ValueVariant::Int(8000))); // boundary inclusive
    assert!(between_pred.evaluate(&ValueVariant::Int(8443))); // boundary inclusive
    assert!(!between_pred.evaluate(&ValueVariant::Int(443)));  // out of range

    // String coercion in range
    assert!(between_pred.evaluate(&ValueVariant::String("8080".to_string())));
    assert!(between_pred.evaluate(&ValueVariant::String("8440.5".to_string())));
    assert!(!between_pred.evaluate(&ValueVariant::String("9000".to_string())));
    assert!(!between_pred.evaluate(&ValueVariant::String("invalid_number".to_string())));

    // Hex string coercion
    let hex_pred = NumericPredicate::new(NumericOp::Equal(255.0));
    assert!(hex_pred.evaluate(&ValueVariant::String("0xFF".to_string())));
    assert!(hex_pred.evaluate(&ValueVariant::String("0xff".to_string())));
}

#[test]
fn test_feature_22_redos_safe_regex_engine() {
    // Nested quantifier pattern known to cause catastrophic exponential backtracking in non-linear engines
    let pattern = r"(a+)+$";
    let matcher = SafeRegexMatcher::compile(pattern, false).expect("Linear DFA compiler should compile (a+)+$");

    // Construct 5,000 'a's ending with 'b' (non-matching)
    let attack_input = format!("{}b", "a".repeat(5000));

    let start = Instant::now();
    let is_match = matcher.is_match(&attack_input);
    let elapsed = start.elapsed();

    assert!(!is_match, "Payload ending with 'b' must not match pattern ending with 'a'");
    assert!(
        elapsed.as_millis() < 50,
        "ReDoS execution must complete in < 50ms under DFA engine (actual: {:?})",
        elapsed
    );

    // Reject dangerous lookarounds at compile time
    let bad_lookaround = r"admin(?=password)";
    assert!(SafeRegexMatcher::compile(bad_lookaround, false).is_err());
}

#[test]
fn test_feature_23_large_set_membership_and_cidr_evaluator() {
    // 1. Benchmark 10,000 items in LargeHashSet
    let mut domains = Vec::with_capacity(10000);
    for i in 0..10000 {
        domains.push(format!("malicious-domain-{:05}.threat.org", i));
    }

    let set_eval = SetEvaluator::from_strings(domains, true);

    let query_val = ValueVariant::String("malicious-domain-04999.threat.org".to_string());
    let missing_val = ValueVariant::String("benign-domain-99999.google.com".to_string());

    let start = Instant::now();
    let iterations = 10_000;
    for _ in 0..iterations {
        assert!(set_eval.contains(&query_val));
        assert!(!set_eval.contains(&missing_val));
    }
    let elapsed = start.elapsed();
    let amortized_ns = (elapsed.as_nanos() as f64) / ((iterations * 2) as f64);
    assert!(
        amortized_ns < 5000.0,
        "Amortized set lookup latency must be fast (actual: {:.2} ns/lookup)",
        amortized_ns
    );

    // 2. Test CIDR Subnet Evaluator
    let cidr_set = SetEvaluator::from_cidrs(&[
        "10.0.0.0/8",
        "192.168.0.0/16",
        "172.16.0.0/12",
        "2001:db8::/32",
    ]).expect("Valid CIDR blocks");

    assert!(cidr_set.contains(&ValueVariant::String("10.50.25.100".to_string())));
    assert!(cidr_set.contains(&ValueVariant::String("192.168.1.1".to_string())));
    assert!(cidr_set.contains(&ValueVariant::String("172.20.10.5".to_string())));
    assert!(!cidr_set.contains(&ValueVariant::String("8.8.8.8".to_string())));
    assert!(!cidr_set.contains(&ValueVariant::String("1.1.1.1".to_string())));
}

#[test]
fn test_feature_24_wildcard_globbing_fidelity() {
    let glob1 = GlobMatcher::compile(r"*\System32\*.dll", true);
    assert!(glob1.is_match(r"C:\Windows\System32\ntdll.dll"));
    assert!(glob1.is_match(r"C:\Windows\System32\kernel32.DLL"));
    assert!(!glob1.is_match(r"C:\Windows\SysWOW64\ntdll.dll"));
    assert!(!glob1.is_match(r"C:\Windows\System32\calc.exe"));

    let glob2 = GlobMatcher::compile(r"svchost?.exe", true);
    assert!(glob2.is_match("svchost1.exe"));
    assert!(glob2.is_match("svchostA.EXE"));
    assert!(!glob2.is_match("svchost.exe"));      // Missing '?' character
    assert!(!glob2.is_match("svchost12.exe"));    // Too many characters

    // Fast-path Prefix / Suffix checks
    let prefix_glob = GlobMatcher::compile("mimikatz*", true);
    assert!(prefix_glob.is_match("mimikatz_x64.exe"));
    assert!(!prefix_glob.is_match("not_mimikatz.exe"));

    let suffix_glob = GlobMatcher::compile("*.ps1", true);
    assert!(suffix_glob.is_match("invoke-mimikatz.ps1"));
    assert!(!suffix_glob.is_match("invoke-mimikatz.ps1.bak"));
}
