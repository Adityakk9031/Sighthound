use ron::error::SpannedError;
use ron::from_str;
use serde::Deserialize;
use sighthound::rules::Rules;

// note: the categorized JavaScript rule files (dom_xss.ron, unsafe_object_operations.ron,
// ...) with `dom_xss_sinks`/`sanitizers` schemas were consolidated into the unified
// `rules: [...]` files `frontend_security.ron` and `frontend_taint_security.ron`. These
// tests now verify those unified files parse via the real `Rules` loader. The two
// schema-agnostic RON-syntax tests below are unchanged.

#[test]
fn test_basic_ron_structure() {
    // RON struct syntax uses parentheses; nested structs are parenthesised too.
    let simple_ron = r#"(
        key: "value",
        number: 42,
        array: [1, 2, 3],
        nested: (
            field: "nested_value"
        )
    )"#;

    #[derive(Deserialize)]
    struct SimpleStruct {
        key: String,
        number: i32,
        array: Vec<i32>,
        nested: NestedStruct,
    }

    #[derive(Deserialize)]
    struct NestedStruct {
        field: String,
    }

    let parsed: SimpleStruct = from_str(simple_ron).expect("Failed to parse basic RON structure");
    assert_eq!(parsed.key, "value");
    assert_eq!(parsed.number, 42);
    assert_eq!(parsed.array, vec![1, 2, 3]);
    assert_eq!(parsed.nested.field, "nested_value");
}

#[test]
fn test_frontend_rules_structure() {
    let rules = Rules::load_from_file("rules/javascript/frontend_security.ron")
        .expect("Failed to load frontend_security.ron");

    // Verify the unified JS rules parsed and look well-formed
    assert!(rules.count_rules() > 0, "frontend_security rules should not be empty");
    for rule in &rules.rules {
        assert!(
            rule.pattern.is_some()
                || rule.patterns.is_some()
                || rule.sources.is_some()
                || rule.sinks.is_some(),
            "each rule should declare a pattern or taint source/sink"
        );
    }
}

#[test]
fn test_ron_syntax_validation() {
    let valid_ron = r#"(
        field: "value",
        array: [1, 2, 3],
        object: (
            nested: "value"
        )
    )"#;

    #[derive(Deserialize)]
    struct TestStruct {
        field: String,
        array: Vec<i32>,
        object: NestedStruct,
    }

    #[derive(Deserialize)]
    struct NestedStruct {
        nested: String,
    }

    let parsed: TestStruct = from_str(valid_ron).expect("Failed to parse valid RON syntax");
    assert_eq!(parsed.field, "value");
    assert_eq!(parsed.array, vec![1, 2, 3]);
    assert_eq!(parsed.object.nested, "value");

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
    let files = ["frontend_security.ron", "frontend_taint_security.ron"];

    for file in files.iter() {
        let path = format!("rules/javascript/{}", file);
        let rules = Rules::load_from_file(&path)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", file, e));
        assert!(rules.count_rules() > 0, "{} should contain rules", file);
    }
}

#[test]
fn test_ron_field_types() {
    let rules = Rules::load_from_file("rules/javascript/frontend_security.ron")
        .expect("Failed to load frontend_security.ron");

    // Verify field types: rules carry finding types and file-type filters
    assert!(
        rules.rules.iter().any(|r| r.finding_type.is_some()),
        "rules should declare finding types"
    );
    assert!(rules.rules.iter().any(|r| r.file_types.is_some()), "rules should declare file types");
}

#[test]
fn test_ron_mode_classification() {
    // The taint rule file should expose taint-mode rules via the unified accessor.
    let rules = Rules::load_from_file("rules/javascript/frontend_taint_security.ron")
        .expect("Failed to load frontend_taint_security.ron");

    assert!(
        !rules.get_taint_rules().is_empty(),
        "frontend_taint_security should contain taint-mode rules"
    );
}
