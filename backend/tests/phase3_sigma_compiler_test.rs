use stream_detect_engine::condition_parser::*;
use stream_detect_engine::field_resolver::*;
use stream_detect_engine::metadata_enricher::{IngressContext, IngressProtocol};
use stream_detect_engine::quarantine_dlq::*;
use stream_detect_engine::rule_ast::*;
use stream_detect_engine::rule_validator::*;
use stream_detect_engine::sigma_parser::*;

#[test]
fn test_feature_13_malformed_event_quarantine() {
    let quarantine = QuarantineManager::new(1024);
    let raw_truncated_payload = b"{\"event_id\": \"truncated_data_123\", \"event_type\": \"auth_fail";

    let ctx = IngressContext {
        gateway_id: "edge-gw-01".to_string(),
        protocol: IngressProtocol::RestHttp,
        client_ip: Some("192.168.1.100".to_string()),
        client_tls_cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
    };

    let id = quarantine
        .quarantine("UNTERMINATED_JSON_BUFFER", raw_truncated_payload, &ctx)
        .expect("Quarantine must succeed");

    assert_eq!(id, 1);
    assert_eq!(quarantine.len(), 1);

    let drained = quarantine.drain(10);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].failure_reason, "UNTERMINATED_JSON_BUFFER");
    assert_eq!(drained[0].source_gateway, "edge-gw-01");
    assert_eq!(drained[0].raw_payload, raw_truncated_payload);
    assert_ne!(drained[0].origin_hash, 0);
}

#[test]
fn test_feature_14_sigma_yaml_parser() {
    let sigma_yaml = r#"
title: Suspicious PowerShell Download Cradle
id: 3b6ab520-22c6-43b8-89c5-34537c35e987
status: experimental
description: Detects suspicious PowerShell download strings and encoded execution
author: Detection Engineering Team
references:
    - https://attack.mitre.org/techniques/T1059/001/
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_cli:
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
            - 'iwr'
    condition: selection_img and selection_cli
fields:
    - CommandLine
    - ParentCommandLine
    - User
level: high
tags:
    - attack.execution
    - attack.t1059.001
"#;

    let parsed = SigmaParser::parse_yaml(sigma_yaml).expect("Sigma YAML parse must succeed");
    assert_eq!(parsed.title, "Suspicious PowerShell Download Cradle");
    assert_eq!(parsed.id, Some("3b6ab520-22c6-43b8-89c5-34537c35e987".to_string()));
    assert_eq!(parsed.logsource.category, Some("process_creation".to_string()));
    assert_eq!(parsed.logsource.product, Some("windows".to_string()));
    assert_eq!(parsed.level, Some("high".to_string()));
    assert!(parsed.detection.contains_key("selection_img"));
    assert!(parsed.detection.contains_key("selection_cli"));
}

#[test]
fn test_feature_15_rule_validation_and_undefined_identifier_trapping() {
    let bad_rule_yaml = r#"
title: Rule Referencing Missing Identifier
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: 'calc.exe'
    condition: selection_1 and selection_missing
level: medium
"#;

    let raw = SigmaParser::parse_yaml(bad_rule_yaml).unwrap();
    let res = RuleValidator::compile_and_validate(&raw);
    assert!(res.is_err(), "Must reject rule with undefined identifier");

    if let Err(e) = res {
        assert_eq!(e.kind, RuleValidationErrorKind::UndefinedIdentifier);
        assert!(e.message.contains("selection_missing"));
    }
}

#[test]
fn test_feature_16_rule_ast_construction_and_integrity() {
    let valid_rule_yaml = r#"
title: Suspicious Cobalt Strike Named Pipe
id: e3b0c442-98fc-1c14-9afb-f4c8996fb924
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|contains:
            - 'msse-'
            - 'status_'
            - 'postex_'
    condition: selection
level: critical
tags:
    - attack.lateral_movement
"#;

    let raw = SigmaParser::parse_yaml(valid_rule_yaml).unwrap();
    let ast = RuleValidator::compile_and_validate(&raw).expect("AST compilation must succeed");

    assert_eq!(ast.title, "Suspicious Cobalt Strike Named Pipe");
    assert_eq!(ast.level, RuleLevel::Critical);
    assert_eq!(ast.logsource.category, Some("pipe_created".to_string()));
    assert_eq!(ast.searches.len(), 1);
    assert!(ast.searches.contains_key("selection"));

    let sel = &ast.searches["selection"];
    assert_eq!(sel.matchers.len(), 1);
    assert_eq!(sel.matchers[0].field, "PipeName");
    assert_eq!(sel.matchers[0].modifiers, vec![ModifierType::Contains]);
    assert_eq!(sel.matchers[0].values.len(), 3);
}

#[test]
fn test_feature_17_field_selector_resolution_and_aliasing() {
    let resolver = FieldResolver::new();

    let r1 = resolver.resolve("CommandLine");
    assert_eq!(r1.canonical_path, "process.command_line");
    assert_eq!(r1.path_segments, vec!["process", "command_line"]);

    let r2 = resolver.resolve("ParentProcessId");
    assert_eq!(r2.canonical_path, "process.parent.pid");
    assert_eq!(r2.path_segments, vec!["process", "parent", "pid"]);

    let r3 = resolver.resolve("DestinationIp");
    assert_eq!(r3.canonical_path, "destination.ip");

    let r4 = resolver.resolve("custom.deep.nested.attribute");
    assert_eq!(r4.canonical_path, "custom.deep.nested.attribute");
    assert_eq!(r4.path_segments, vec!["custom", "deep", "nested", "attribute"]);
}

#[test]
fn test_feature_18_complex_boolean_condition_parsing() {
    let expr_str = "selection1 and (selection2 or not selection3) and 1 of filter_*";
    let ast = ConditionParser::parse(expr_str).expect("Condition parse must succeed");

    match ast {
        ConditionExpr::And(list) => {
            assert_eq!(list.len(), 3);
            assert_eq!(list[0], ConditionExpr::SearchRef("selection1".to_string()));

            // list[1] is (selection2 or not selection3)
            match &list[1] {
                ConditionExpr::Or(or_list) => {
                    assert_eq!(or_list.len(), 2);
                    assert_eq!(or_list[0], ConditionExpr::SearchRef("selection2".to_string()));
                    match &or_list[1] {
                        ConditionExpr::Not(inner) => {
                            assert_eq!(**inner, ConditionExpr::SearchRef("selection3".to_string()));
                        }
                        _ => panic!("Expected Not node in Or branch"),
                    }
                }
                _ => panic!("Expected Or node in middle of And expression"),
            }

            // list[2] is 1 of filter_*
            assert_eq!(list[2], ConditionExpr::OneOf("filter_*".to_string()));
        }
        _ => panic!("Expected top-level And node"),
    }
}
