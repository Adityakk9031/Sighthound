use sighthound::rules::Rules;
use std::fs;
use std::path::Path;

// note: the categorized JavaScript rule files were consolidated into the unified
// `frontend_security.ron` / `frontend_taint_security.ron`. These tests now load those
// files via the real `Rules` loader and verify the matching test fixtures (which moved to
// tests/test_files/javascript/) contain the dangerous patterns the rules target.

fn load_frontend_rules() -> Rules {
    Rules::load_from_file("rules/javascript/frontend_security.ron")
        .expect("Failed to load frontend_security.ron")
}

#[test]
fn test_dom_xss_rules() {
    let rules = load_frontend_rules();

    // Verify structure: the consolidated rule set is non-empty and XSS rules exist
    assert!(rules.count_rules() > 0, "frontend rules should not be empty");
    assert!(
        rules.rules.iter().any(|r| r.finding_type.as_deref().map(|t| t.contains("XSS")).unwrap_or(false)
            || r.category.as_deref() == Some("xss")),
        "should contain DOM XSS rules"
    );

    // Verify test fixture
    let fixtures = Path::new("tests/test_files/javascript");
    let test_file = fs::read_to_string(fixtures.join("dom_xss_test.js"))
        .expect("Failed to read dom_xss_test.js");
    assert!(test_file.contains("innerHTML"), "Test file should contain innerHTML");
    assert!(test_file.contains("document.write"), "Test file should contain document.write");
}

#[test]
fn test_unsafe_object_rules() {
    let rules = load_frontend_rules();

    // Verify structure
    assert!(rules.count_rules() > 0, "frontend rules should not be empty");

    // Verify test fixture
    let fixtures = Path::new("tests/test_files/javascript");
    let test_file = fs::read_to_string(fixtures.join("unsafe_object_test.js"))
        .expect("Failed to read unsafe_object_test.js");
    assert!(test_file.contains("JSON.parse"), "Test file should contain JSON.parse");
    assert!(test_file.contains("Object.assign"), "Test file should contain Object.assign");
}

#[test]
fn test_code_injection_rules() {
    let rules = load_frontend_rules();

    // Verify structure
    assert!(rules.count_rules() > 0, "frontend rules should not be empty");

    // Verify test fixture
    let fixtures = Path::new("tests/test_files/javascript");
    let test_file = fs::read_to_string(fixtures.join("code_injection_test.js"))
        .expect("Failed to read code_injection_test.js");
    assert!(test_file.contains("new Function"), "Test file should contain new Function");
    assert!(test_file.contains("setTimeout"), "Test file should contain setTimeout");
}

#[test]
fn test_rule_well_formedness() {
    // note: the consolidated rules express logic via patterns/sources/sinks rather than the
    // old per-sink `conditions` lists, so we assert each rule carries actionable matching data.
    let rules = load_frontend_rules();

    for rule in &rules.rules {
        assert!(
            rule.pattern.is_some() || rule.patterns.is_some()
                || rule.sources.is_some() || rule.sinks.is_some(),
            "each rule should declare a pattern or taint source/sink"
        );
    }
}

#[test]
fn test_file_type_patterns() {
    let rules = load_frontend_rules();

    // At least some rules declare file-type filters with JS/TS extensions
    assert!(
        rules.rules.iter().any(|r| r.file_types.as_ref()
            .and_then(|ft| ft.extensions.as_ref())
            .map(|exts| !exts.is_empty())
            .unwrap_or(false)),
        "rules should declare file_types extensions"
    );
}
