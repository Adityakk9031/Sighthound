// TODO(onboarding): Rules::malware_detection schema removed during crate rename; needs triage.
// Module is currently excluded from tests/unit/main.rs so the rest of the suite still compiles.
use sighthound::rules::Rules;
use tempfile::NamedTempFile;
use std::io::Write;

#[cfg(test)]
mod deserialization_tests {
    use super::*;

    #[test]
    fn test_clean_syntax_single_pattern() {
        let ron_content = r#"{
            malware_detection: Some([
                (
                    pattern: "pyperclip.paste",
                    finding_type: Some("clipboard_access"),
                    conditions: None,
                    file_types: Some((
                        extensions: [".py"],
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]),
        }"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse clean syntax RON");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 1);
        
        let rule = &malware_rules[0];
        assert_eq!(rule.pattern, Some("pyperclip.paste".to_string()));
        assert_eq!(rule.patterns, None);
        assert_eq!(rule.finding_type, Some("clipboard_access".to_string()));
        
        let file_types = rule.file_types.as_ref().unwrap();
        assert_eq!(file_types.extensions, Some(vec![".py".to_string()]));
    }

    #[test]
    fn test_explicit_syntax_single_pattern() {
        let ron_content = r#"{
            malware_detection: Some([
                (
                    pattern: Some("pyperclip.paste"),
                    finding_type: Some("clipboard_access"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]),
        }"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse explicit syntax RON");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 1);
        
        let rule = &malware_rules[0];
        assert_eq!(rule.pattern, Some("pyperclip.paste".to_string()));
        assert_eq!(rule.patterns, None);
        assert_eq!(rule.finding_type, Some("clipboard_access".to_string()));
    }

    #[test]
    fn test_clean_syntax_multiple_patterns() {
        let ron_content = r#"{
            malware_detection: Some([
                (
                    patterns: [
                        "pyperclip.paste",
                        "pyperclip.copy",
                        "*.to_clipboard",
                    ],
                    finding_type: Some("clipboard_access"),
                    conditions: None,
                    file_types: Some((
                        extensions: [".py"],
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]),
        }"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse clean multiple patterns RON");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 1);
        
        let rule = &malware_rules[0];
        assert_eq!(rule.pattern, None);
        assert_eq!(rule.patterns, Some(vec![
            "pyperclip.paste".to_string(),
            "pyperclip.copy".to_string(),
            "*.to_clipboard".to_string(),
        ]));
        assert_eq!(rule.finding_type, Some("clipboard_access".to_string()));
    }

    #[test]
    fn test_explicit_syntax_multiple_patterns() {
        let ron_content = r#"{
            malware_detection: Some([
                (
                    patterns: Some([
                        "pyperclip.paste",
                        "pyperclip.copy",
                        "*.to_clipboard",
                    ]),
                    finding_type: Some("clipboard_access"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]),
        }"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse explicit multiple patterns RON");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 1);
        
        let rule = &malware_rules[0];
        assert_eq!(rule.pattern, None);
        assert_eq!(rule.patterns, Some(vec![
            "pyperclip.paste".to_string(),
            "pyperclip.copy".to_string(),
            "*.to_clipboard".to_string(),
        ]));
    }

    #[test]
    fn test_mixed_syntax_compatibility() {
        let ron_content = r#"{
            malware_detection: Some([
                (
                    pattern: "single_pattern_clean",
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: None,
                ),
                (
                    pattern: Some("single_pattern_explicit"),
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: None,
                ),
                (
                    patterns: [
                        "multi_pattern_clean_1",
                        "multi_pattern_clean_2",
                    ],
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: None,
                ),
                (
                    patterns: Some([
                        "multi_pattern_explicit_1",
                        "multi_pattern_explicit_2",
                    ]),
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: None,
                ),
            ]),
        }"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse mixed syntax RON");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 4);
        
        // Test clean single pattern
        assert_eq!(malware_rules[0].pattern, Some("single_pattern_clean".to_string()));
        assert_eq!(malware_rules[0].patterns, None);
        
        // Test explicit single pattern
        assert_eq!(malware_rules[1].pattern, Some("single_pattern_explicit".to_string()));
        assert_eq!(malware_rules[1].patterns, None);
        
        // Test clean multiple patterns
        assert_eq!(malware_rules[2].pattern, None);
        assert_eq!(malware_rules[2].patterns, Some(vec![
            "multi_pattern_clean_1".to_string(),
            "multi_pattern_clean_2".to_string(),
        ]));
        
        // Test explicit multiple patterns
        assert_eq!(malware_rules[3].pattern, None);
        assert_eq!(malware_rules[3].patterns, Some(vec![
            "multi_pattern_explicit_1".to_string(),
            "multi_pattern_explicit_2".to_string(),
        ]));
    }

    #[test]
    fn test_conditions_with_clean_syntax() {
        let ron_content = r#"{
            malware_detection: Some([
                (
                    pattern: "subprocess.Popen",
                    finding_type: Some("command_injection"),
                    conditions: Some([
                        (
                            type: "has_argument",
                            pattern: "shell=True",
                            name: None,
                            not_in: None,
                            parent_type: None,
                        ),
                        (
                            type: "has_argument",
                            patterns: ["*.exe*", "*.bat*"],
                            name: None,
                            not_in: None,
                            parent_type: None,
                        ),
                    ]),
                    file_types: Some((
                        extensions: [".py"],
                        include_patterns: ["*test*"],
                        exclude_patterns: ["*safe*"],
                    )),
                ),
            ]),
        }"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse conditions with clean syntax");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 1);
        
        let rule = &malware_rules[0];
        assert_eq!(rule.pattern, Some("subprocess.Popen".to_string()));
        
        let conditions = rule.conditions.as_ref().unwrap();
        assert_eq!(conditions.len(), 2);
        
        // First condition with single pattern
        assert_eq!(conditions[0].pattern, Some("shell=True".to_string()));
        assert_eq!(conditions[0].patterns, None);
        
        // Second condition with multiple patterns
        assert_eq!(conditions[1].pattern, None);
        assert_eq!(conditions[1].patterns, Some(vec![
            "*.exe*".to_string(),
            "*.bat*".to_string(),
        ]));
        
        // Test file types
        let file_types = rule.file_types.as_ref().unwrap();
        assert_eq!(file_types.extensions, Some(vec![".py".to_string()]));
        assert_eq!(file_types.include_patterns, Some(vec!["*test*".to_string()]));
        assert_eq!(file_types.exclude_patterns, Some(vec!["*safe*".to_string()]));
    }

    #[test]
    fn test_file_loading_and_parsing() {
        let ron_content = r#"{
            malware_detection: Some([
                (
                    patterns: [
                        "keyboard.hook",
                        "keyboard.on_press",
                        "pynput.*",
                    ],
                    finding_type: Some("keylogger"),
                    severity: Some("high"),
                    confidence: Some("medium"),
                    conditions: None,
                    file_types: Some((
                        extensions: [".py", ".pyw"],
                        include_patterns: None,
                        exclude_patterns: ["*test*", "*demo*"],
                    )),
                ),
            ]),
            injection_sinks: Some([
                (
                    pattern: "cursor.execute",
                    finding_type: Some("sql_injection"),
                    conditions: Some([
                        (
                            type: "has_argument",
                            pattern: "*SELECT*",
                            name: None,
                            not_in: None,
                            parent_type: None,
                        ),
                    ]),
                    file_types: Some((
                        extensions: [".py"],
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]),
        }"#;

        // Create a temporary file with .ron extension
        let mut temp_file = NamedTempFile::with_suffix(".ron").expect("Failed to create temp file");
        write!(temp_file, "{}", ron_content).expect("Failed to write to temp file");

        // Test loading from file
        let rules = Rules::load_from_file(temp_file.path().to_str().unwrap())
            .expect("Failed to load rules from file");

        // Verify malware detection rules
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 1);
        
        let keylogger_rule = &malware_rules[0];
        assert_eq!(keylogger_rule.patterns, Some(vec![
            "keyboard.hook".to_string(),
            "keyboard.on_press".to_string(),
            "pynput.*".to_string(),
        ]));
        assert_eq!(keylogger_rule.severity, Some("high".to_string()));
        assert_eq!(keylogger_rule.confidence, Some("medium".to_string()));

        // Verify injection sinks
        let injection_rules = rules.injection_sinks.unwrap();
        assert_eq!(injection_rules.len(), 1);
        
        let sql_rule = &injection_rules[0];
        assert_eq!(sql_rule.pattern, Some("cursor.execute".to_string()));
        assert_eq!(sql_rule.finding_type, Some("sql_injection".to_string()));
    }

    #[test]
    fn test_error_handling_invalid_syntax() {
        // Test invalid RON - both pattern and patterns
        let invalid_ron = r#"{
            malware_detection: Some([
                (
                    pattern: "test",
                    patterns: ["test1", "test2"],
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: None,
                ),
            ]),
        }"#;

        // This should parse successfully (validation happens separately)
        let rules: Result<Rules, _> = ron::from_str(invalid_ron);
        assert!(rules.is_ok(), "RON parsing should succeed even with invalid rule structure");
    }

    #[test]
    fn test_backward_compatibility() {
        // Test that old explicit syntax still works
        let old_syntax_ron = r#"{
            malware_detection: Some([
                (
                    pattern: Some("old_style_pattern"),
                    patterns: None,
                    finding_type: Some("test"),
                    conditions: Some([
                        (
                            type: "has_argument",
                            pattern: Some("*old_style_condition*"),
                            patterns: None,
                            name: None,
                            not_in: None,
                            parent_type: None,
                        ),
                    ]),
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: Some(["*old*"]),
                        exclude_patterns: Some(["*new*"]),
                    )),
                ),
            ]),
        }"#;

        let rules: Rules = ron::from_str(old_syntax_ron)
            .expect("Failed to parse backward compatibility RON");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 1);
        
        let rule = &malware_rules[0];
        assert_eq!(rule.pattern, Some("old_style_pattern".to_string()));
        
        let conditions = rule.conditions.as_ref().unwrap();
        assert_eq!(conditions[0].pattern, Some("*old_style_condition*".to_string()));
        
        let file_types = rule.file_types.as_ref().unwrap();
        assert_eq!(file_types.extensions, Some(vec![".py".to_string()]));
        assert_eq!(file_types.include_patterns, Some(vec!["*old*".to_string()]));
        assert_eq!(file_types.exclude_patterns, Some(vec!["*new*".to_string()]));
    }

    #[test]
    fn test_none_values() {
        let ron_content = r#"{
            malware_detection: Some([
                (
                    pattern: None,
                    patterns: ["test"],
                    finding_type: None,
                    conditions: None,
                    file_types: None,
                ),
            ]),
        }"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse RON with None values");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 1);
        
        let rule = &malware_rules[0];
        assert_eq!(rule.pattern, None);
        assert_eq!(rule.patterns, Some(vec!["test".to_string()]));
        assert_eq!(rule.finding_type, None);
        assert!(rule.conditions.is_none());
        assert!(rule.file_types.is_none());
    }

    #[test]
    fn test_empty_arrays() {
        let ron_content = r#"{
            malware_detection: Some([
                (
                    patterns: [],
                    finding_type: Some("test"),
                    conditions: Some([]),
                    file_types: Some((
                        extensions: [],
                        include_patterns: [],
                        exclude_patterns: [],
                    )),
                ),
            ]),
        }"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse RON with empty arrays");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 1);
        
        let rule = &malware_rules[0];
        assert!(rule.patterns.is_some());
        assert_eq!(rule.patterns.as_ref().unwrap().len(), 0);
        assert!(rule.conditions.is_some());
        assert_eq!(rule.conditions.as_ref().unwrap().len(), 0);
        
        let file_types = rule.file_types.as_ref().unwrap();
        assert!(file_types.extensions.is_some());
        assert_eq!(file_types.extensions.as_ref().unwrap().len(), 0);
        assert!(file_types.include_patterns.is_some());
        assert_eq!(file_types.include_patterns.as_ref().unwrap().len(), 0);
        assert!(file_types.exclude_patterns.is_some());
        assert_eq!(file_types.exclude_patterns.as_ref().unwrap().len(), 0);
    }
} 