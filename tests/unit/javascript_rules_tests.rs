use ron::error::SpannedError;
use ron::from_str;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct Condition {
    #[serde(rename = "type")]
    type_: String,
    #[serde(default)]
    argument_position: Option<usize>,
    #[serde(default)]
    not_in: Option<Vec<String>>,
    #[serde(default)]
    patterns: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct Sink {
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    patterns: Option<Vec<String>>,
    finding_type: String,
    severity: String,
    confidence: String,
    conditions: Vec<Condition>,
}

#[derive(Debug, Deserialize)]
struct FileTypes {
    extensions: Vec<String>,
    exclude_patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DomXssRule {
    dom_xss_sinks: Vec<Sink>,
    sanitizers: Vec<String>,
    file_types: FileTypes,
}

#[derive(Debug, Deserialize)]
struct UnsafeObjectRule {
    unsafe_operations: Vec<Sink>,
    file_types: FileTypes,
}

#[derive(Debug, Deserialize)]
struct CodeInjectionRule {
    injection_patterns: Vec<Sink>,
    file_types: FileTypes,
}

#[test]
fn test_dom_xss_rules() {
    let rules_dir = Path::new("rules/javascript");
    let content =
        fs::read_to_string(rules_dir.join("dom_xss.ron")).expect("Failed to read dom_xss.ron");

    let result: Result<DomXssRule, SpannedError> = from_str(&content);
    assert!(result.is_ok(), "Failed to parse dom_xss.ron");

    if let Ok(rule) = result {
        // Verify structure
        assert!(!rule.dom_xss_sinks.is_empty(), "dom_xss_sinks should not be empty");
        assert!(!rule.sanitizers.is_empty(), "sanitizers should not be empty");
        assert!(
            !rule.file_types.extensions.is_empty(),
            "file_types.extensions should not be empty"
        );

        // Verify test file
        let test_file = fs::read_to_string(rules_dir.join("dom_xss_test.js"))
            .expect("Failed to read dom_xss_test.js");
        assert!(test_file.contains("innerHTML"), "Test file should contain innerHTML");
        assert!(test_file.contains("document.write"), "Test file should contain document.write");
    }
}

#[test]
fn test_unsafe_object_rules() {
    let rules_dir = Path::new("rules/javascript");
    let content = fs::read_to_string(rules_dir.join("unsafe_object_operations.ron"))
        .expect("Failed to read unsafe_object_operations.ron");

    let result: Result<UnsafeObjectRule, SpannedError> = from_str(&content);
    assert!(result.is_ok(), "Failed to parse unsafe_object_operations.ron");

    if let Ok(rule) = result {
        // Verify structure
        assert!(!rule.unsafe_operations.is_empty(), "unsafe_operations should not be empty");
        assert!(
            !rule.file_types.extensions.is_empty(),
            "file_types.extensions should not be empty"
        );

        // Verify test file
        let test_file = fs::read_to_string(rules_dir.join("unsafe_object_test.js"))
            .expect("Failed to read unsafe_object_test.js");
        assert!(test_file.contains("JSON.parse"), "Test file should contain JSON.parse");
        assert!(test_file.contains("eval"), "Test file should contain eval");
    }
}

#[test]
fn test_code_injection_rules() {
    let rules_dir = Path::new("rules/javascript");
    let content = fs::read_to_string(rules_dir.join("code_injection.ron"))
        .expect("Failed to read code_injection.ron");

    let result: Result<CodeInjectionRule, SpannedError> = from_str(&content);
    assert!(result.is_ok(), "Failed to parse code_injection.ron");

    if let Ok(rule) = result {
        // Verify structure
        assert!(!rule.injection_patterns.is_empty(), "injection_patterns should not be empty");
        assert!(
            !rule.file_types.extensions.is_empty(),
            "file_types.extensions should not be empty"
        );

        // Verify test file
        let test_file = fs::read_to_string(rules_dir.join("code_injection_test.js"))
            .expect("Failed to read code_injection_test.js");
        assert!(test_file.contains("new Function"), "Test file should contain new Function");
        assert!(test_file.contains("setTimeout"), "Test file should contain setTimeout");
    }
}

#[test]
fn test_rule_conditions() {
    let rules_dir = Path::new("rules/javascript");
    let content =
        fs::read_to_string(rules_dir.join("dom_xss.ron")).expect("Failed to read dom_xss.ron");

    let result: Result<DomXssRule, SpannedError> = from_str(&content);
    assert!(result.is_ok(), "Failed to parse dom_xss.ron");

    if let Ok(rule) = result {
        if let Some(first_sink) = rule.dom_xss_sinks.first() {
            assert!(!first_sink.conditions.is_empty(), "Sink should have conditions");
            if let Some(first_condition) = first_sink.conditions.first() {
                assert!(!first_condition.type_.is_empty(), "Condition should have type field");
            }
        }
    }
}

#[test]
fn test_file_type_patterns() {
    let rules_dir = Path::new("rules/javascript");
    let files = ["dom_xss.ron", "unsafe_object_operations.ron", "code_injection.ron"];

    for file in files.iter() {
        let content =
            fs::read_to_string(rules_dir.join(file)).expect(&format!("Failed to read {}", file));

        let result: Result<DomXssRule, SpannedError> = from_str(&content);
        assert!(result.is_ok(), "Failed to parse {}", file);

        if let Ok(rule) = result {
            assert!(
                !rule.file_types.extensions.is_empty(),
                "file_types.extensions should not be empty"
            );
            assert!(
                !rule.file_types.exclude_patterns.is_empty(),
                "file_types.exclude_patterns should not be empty"
            );
        }
    }
}
