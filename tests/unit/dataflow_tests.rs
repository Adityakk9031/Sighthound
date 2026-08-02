use sighthound::models::UnifiedRule;
use sighthound::scanner::dataflow::DataFlowTracer;
use sighthound::scanner::flow_tracker::AnalysisResult;
use sighthound::scanner::taint_utils::TaintRuleDeduplicator;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_cyclic_variable_dependency_does_not_stack_overflow() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let code = r#"
def test_func():
    a = b
    b = a
    sink(a)
"#;
    temp_file.write_all(code.as_bytes()).unwrap();
    let path_str = temp_file.path().to_str().unwrap();

    let rule = UnifiedRule {
        id: Some("test_rule".to_string()),
        name: Some("Test Rule".to_string()),
        description: None,
        category: None,
        mode: "taint".to_string(),
        pattern: None,
        patterns: None,
        sources: Some(vec!["source_func()".to_string()]),
        sinks: Some(vec!["sink".to_string()]),
        propagators: None,
        sanitizers: None,
        conditions: None,
        message: None,
        finding_type: None,
        file_types: None,
        severity: None,
        confidence: None,
        cwe_id: None,
        tags: None,
    };

    let rules = vec![&rule];
    let deduplicator = TaintRuleDeduplicator::new(&rules);
    let mut tracer = DataFlowTracer::new();

    let result = tracer.analyze_sink_variable(path_str, "test_func", "a", "sink", 5, &deduplicator);
    assert!(matches!(result, AnalysisResult::DefinitelySafe | AnalysisResult::Unknown { .. }));
}

#[test]
fn test_rule_fingerprint_cache_isolation() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let code = r#"
def test_func():
    var = input()
"#;
    temp_file.write_all(code.as_bytes()).unwrap();
    let path_str = temp_file.path().to_str().unwrap();

    let rule1 = UnifiedRule {
        id: Some("rule1".to_string()),
        name: Some("Rule 1".to_string()),
        description: None,
        category: None,
        mode: "taint".to_string(),
        pattern: None,
        patterns: None,
        sources: Some(vec!["input(".to_string()]),
        sinks: Some(vec!["sink1".to_string()]),
        propagators: None,
        sanitizers: None,
        conditions: None,
        message: None,
        finding_type: None,
        file_types: None,
        severity: None,
        confidence: None,
        cwe_id: None,
        tags: None,
    };

    let rule2 = UnifiedRule {
        id: Some("rule2".to_string()),
        name: Some("Rule 2".to_string()),
        description: None,
        category: None,
        mode: "taint".to_string(),
        pattern: None,
        patterns: None,
        sources: Some(vec!["different_source()".to_string()]),
        sinks: Some(vec!["sink2".to_string()]),
        propagators: None,
        sanitizers: None,
        conditions: None,
        message: None,
        finding_type: None,
        file_types: None,
        severity: None,
        confidence: None,
        cwe_id: None,
        tags: None,
    };

    let rules1 = vec![&rule1];
    let dedup1 = TaintRuleDeduplicator::new(&rules1);

    let rules2 = vec![&rule2];
    let dedup2 = TaintRuleDeduplicator::new(&rules2);

    let mut tracer = DataFlowTracer::new();

    let result1 = tracer.analyze_sink_variable(path_str, "test_func", "var", "sink1", 3, &dedup1);
    let result2 = tracer.analyze_sink_variable(path_str, "test_func", "var", "sink2", 3, &dedup2);

    assert!(matches!(result1, AnalysisResult::DefinitelyTainted { .. }));
    assert!(!matches!(result2, AnalysisResult::DefinitelyTainted { .. }));
}
