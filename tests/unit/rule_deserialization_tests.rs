use sighthound::rules::Rules;
use tempfile::NamedTempFile;
use std::io::Write;

// note: the categorized rule model (`malware_detection`, `injection_sinks`, ...) was
// replaced by a single unified `rules: [...]` list of UnifiedRule. RON also dropped the
// implicit-Option "clean" syntax, so Option fields now require explicit `Some(...)`/`None`.
// Conditions now use the `field`/`operator`/`value` schema (plus optional pattern/patterns).
#[cfg(test)]
mod deserialization_tests {
    use super::*;

    #[test]
    fn test_single_pattern() {
        let ron_content = r#"(
            rules: [
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
            ]
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse single pattern RON");

        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert_eq!(rule.pattern, Some("pyperclip.paste".to_string()));
        assert_eq!(rule.patterns, None);
        assert_eq!(rule.finding_type, Some("clipboard_access".to_string()));

        let file_types = rule.file_types.as_ref().unwrap();
        assert_eq!(file_types.extensions, Some(vec![".py".to_string()]));
    }

    #[test]
    fn test_multiple_patterns() {
        let ron_content = r#"(
            rules: [
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
            ]
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse multiple patterns RON");

        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert_eq!(rule.pattern, None);
        assert_eq!(rule.patterns, Some(vec![
            "pyperclip.paste".to_string(),
            "pyperclip.copy".to_string(),
            "*.to_clipboard".to_string(),
        ]));
        assert_eq!(rule.finding_type, Some("clipboard_access".to_string()));
    }

    #[test]
    fn test_mixed_single_and_multiple_patterns() {
        let ron_content = r#"(
            rules: [
                (
                    pattern: Some("single_pattern_a"),
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: None,
                ),
                (
                    pattern: Some("single_pattern_b"),
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: None,
                ),
                (
                    patterns: Some([
                        "multi_pattern_1",
                        "multi_pattern_2",
                    ]),
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: None,
                ),
                (
                    patterns: Some([
                        "multi_pattern_3",
                        "multi_pattern_4",
                    ]),
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: None,
                ),
            ]
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse mixed syntax RON");

        assert_eq!(rules.rules.len(), 4);

        assert_eq!(rules.rules[0].pattern, Some("single_pattern_a".to_string()));
        assert_eq!(rules.rules[0].patterns, None);

        assert_eq!(rules.rules[1].pattern, Some("single_pattern_b".to_string()));
        assert_eq!(rules.rules[1].patterns, None);

        assert_eq!(rules.rules[2].pattern, None);
        assert_eq!(rules.rules[2].patterns, Some(vec![
            "multi_pattern_1".to_string(),
            "multi_pattern_2".to_string(),
        ]));

        assert_eq!(rules.rules[3].pattern, None);
        assert_eq!(rules.rules[3].patterns, Some(vec![
            "multi_pattern_3".to_string(),
            "multi_pattern_4".to_string(),
        ]));
    }

    #[test]
    fn test_conditions_parsing() {
        let ron_content = r#"(
            rules: [
                (
                    pattern: Some("subprocess.Popen"),
                    finding_type: Some("command_injection"),
                    conditions: Some([
                        (
                            field: "has_argument",
                            operator: "contains",
                            value: "shell=True",
                            pattern: Some("shell=True"),
                        ),
                        (
                            field: "has_argument",
                            operator: "matches",
                            value: "executables",
                            patterns: Some(["*.exe*", "*.bat*"]),
                        ),
                    ]),
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: Some(["*test*"]),
                        exclude_patterns: Some(["*safe*"]),
                    )),
                ),
            ]
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse conditions RON");

        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
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
        // note: a keylogger (malware) rule and a SQL-injection sink rule now live together
        // in one unified `rules` list rather than separate categories.
        let ron_content = r#"(
            rules: [
                (
                    patterns: Some([
                        "keyboard.hook",
                        "keyboard.on_press",
                        "pynput.*",
                    ]),
                    finding_type: Some("keylogger"),
                    severity: Some("high"),
                    confidence: Some("medium"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py", ".pyw"]),
                        include_patterns: None,
                        exclude_patterns: Some(["*test*", "*demo*"]),
                    )),
                ),
                (
                    pattern: Some("cursor.execute"),
                    finding_type: Some("sql_injection"),
                    conditions: Some([
                        (
                            field: "has_argument",
                            operator: "contains",
                            value: "select",
                            pattern: Some("*SELECT*"),
                        ),
                    ]),
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]
        )"#;

        // Create a temporary file with .ron extension
        let mut temp_file = NamedTempFile::with_suffix(".ron").expect("Failed to create temp file");
        write!(temp_file, "{}", ron_content).expect("Failed to write to temp file");

        // Test loading from file
        let rules = Rules::load_from_file(temp_file.path().to_str().unwrap())
            .expect("Failed to load rules from file");

        assert_eq!(rules.rules.len(), 2);

        let keylogger_rule = &rules.rules[0];
        assert_eq!(keylogger_rule.patterns, Some(vec![
            "keyboard.hook".to_string(),
            "keyboard.on_press".to_string(),
            "pynput.*".to_string(),
        ]));
        assert_eq!(keylogger_rule.severity, Some("high".to_string()));
        assert_eq!(keylogger_rule.confidence, Some("medium".to_string()));

        let sql_rule = &rules.rules[1];
        assert_eq!(sql_rule.pattern, Some("cursor.execute".to_string()));
        assert_eq!(sql_rule.finding_type, Some("sql_injection".to_string()));
    }

    #[test]
    fn test_parsing_succeeds_with_both_pattern_and_patterns() {
        // A rule that sets both `pattern` and `patterns` still parses; structural
        // validation (if any) happens separately from deserialization.
        let ron_content = r#"(
            rules: [
                (
                    pattern: Some("test"),
                    patterns: Some(["test1", "test2"]),
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: None,
                ),
            ]
        )"#;

        let rules: Result<Rules, _> = ron::from_str(ron_content);
        assert!(rules.is_ok(), "RON parsing should succeed even with both pattern and patterns set");
    }

    #[test]
    fn test_explicit_option_syntax() {
        // The explicit `Some(...)`/`None` Option syntax is the supported form.
        let ron_content = r#"(
            rules: [
                (
                    pattern: Some("explicit_pattern"),
                    patterns: None,
                    finding_type: Some("test"),
                    conditions: Some([
                        (
                            field: "has_argument",
                            operator: "contains",
                            value: "marker",
                            pattern: Some("*marker*"),
                            patterns: None,
                        ),
                    ]),
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: Some(["*old*"]),
                        exclude_patterns: Some(["*new*"]),
                    )),
                ),
            ]
        )"#;

        let rules: Rules = ron::from_str(ron_content)
            .expect("Failed to parse explicit Option syntax RON");

        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert_eq!(rule.pattern, Some("explicit_pattern".to_string()));

        let conditions = rule.conditions.as_ref().unwrap();
        assert_eq!(conditions[0].pattern, Some("*marker*".to_string()));

        let file_types = rule.file_types.as_ref().unwrap();
        assert_eq!(file_types.extensions, Some(vec![".py".to_string()]));
        assert_eq!(file_types.include_patterns, Some(vec!["*old*".to_string()]));
        assert_eq!(file_types.exclude_patterns, Some(vec!["*new*".to_string()]));
    }

    #[test]
    fn test_none_values() {
        let ron_content = r#"(
            rules: [
                (
                    pattern: None,
                    patterns: Some(["test"]),
                    finding_type: None,
                    conditions: None,
                    file_types: None,
                ),
            ]
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse RON with None values");

        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert_eq!(rule.pattern, None);
        assert_eq!(rule.patterns, Some(vec!["test".to_string()]));
        assert_eq!(rule.finding_type, None);
        assert!(rule.conditions.is_none());
        assert!(rule.file_types.is_none());
    }

    #[test]
    fn test_empty_arrays() {
        let ron_content = r#"(
            rules: [
                (
                    patterns: Some([]),
                    finding_type: Some("test"),
                    conditions: Some([]),
                    file_types: Some((
                        extensions: Some([]),
                        include_patterns: Some([]),
                        exclude_patterns: Some([]),
                    )),
                ),
            ]
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse RON with empty arrays");

        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
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
