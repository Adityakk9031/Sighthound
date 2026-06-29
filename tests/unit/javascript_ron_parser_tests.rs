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

#[test]
fn test_basic_ron_structure() {
    let simple_ron = r#"{
        key: "value",
        number: 42,
        array: [1, 2, 3],
        nested: {
            field: "nested_value"
        }
    }"#;

    #[derive(Debug, Deserialize)]
    struct SimpleStruct {
        key: String,
        number: i32,
        array: Vec<i32>,
        nested: NestedStruct,
    }

    #[derive(Debug, Deserialize)]
    struct NestedStruct {
        field: String,
    }

    let result: Result<SimpleStruct, SpannedError> = from_str(simple_ron);
    assert!(result.is_ok(), "Failed to parse basic RON structure");
}

#[test]
fn test_dom_xss_ron_structure() {
    let rules_dir = Path::new("rules/javascript");
    let content =
        fs::read_to_string(rules_dir.join("dom_xss.ron")).expect("Failed to read dom_xss.ron");

    let result: Result<DomXssRule, SpannedError> = from_str(&content);
    assert!(result.is_ok(), "Failed to parse dom_xss.ron");

    if let Ok(rule) = result {
        // Verify required fields
        assert!(!rule.dom_xss_sinks.is_empty(), "dom_xss_sinks should not be empty");
        assert!(!rule.sanitizers.is_empty(), "sanitizers should not be empty");
        assert!(
            !rule.file_types.extensions.is_empty(),
            "file_types.extensions should not be empty"
        );
    }
}

#[test]
fn test_ron_syntax_validation() {
    let valid_ron = r#"{
        field: "value",
        array: [1, 2, 3],
        object: {
            nested: "value"
        }
    }"#;

    #[derive(Debug, Deserialize)]
    struct TestStruct {
        field: String,
        array: Vec<i32>,
        object: NestedStruct,
    }

    #[derive(Debug, Deserialize)]
    struct NestedStruct {
        nested: String,
    }

    let result: Result<TestStruct, SpannedError> = from_str(valid_ron);
    assert!(result.is_ok(), "Failed to parse valid RON syntax");

    let invalid_ron = r#"{
        field: "value",
        array: [1, 2, 3,
        object: {
            nested: "value"
        }
    }"#;

    let result: Result<TestStruct, SpannedError> = from_str(invalid_ron);
    assert!(result.is_err(), "Should fail to parse invalid RON syntax");
}

#[test]
fn test_rule_file_parsing() {
    let rules_dir = Path::new("rules/javascript");
    let files = [
        "dom_xss.ron",
        "unsafe_object_operations.ron",
        "unsafe_navigation.ron",
        "data_exposure.ron",
        "code_injection.ron",
        "event_handler_injection.ron",
    ];

    for file in files.iter() {
        let content =
            fs::read_to_string(rules_dir.join(file)).expect(&format!("Failed to read {}", file));

        let result: Result<DomXssRule, SpannedError> = from_str(&content);
        assert!(result.is_ok(), "Failed to parse {}", file);
    }
}

#[test]
fn test_ron_field_types() {
    let rules_dir = Path::new("rules/javascript");
    let content =
        fs::read_to_string(rules_dir.join("dom_xss.ron")).expect("Failed to read dom_xss.ron");

    let result: Result<DomXssRule, SpannedError> = from_str(&content);
    assert!(result.is_ok(), "Failed to parse dom_xss.ron");

    if let Ok(rule) = result {
        // Verify field types
        assert!(!rule.dom_xss_sinks.is_empty(), "dom_xss_sinks should not be empty");
        assert!(!rule.sanitizers.is_empty(), "sanitizers should not be empty");
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

#[test]
fn test_ron_condition_structure() {
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
