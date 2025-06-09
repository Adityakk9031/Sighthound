use find_vulns::rules::{Rules, rule_matches_pattern, validate_rule_patterns};
use tempfile::{NamedTempFile};
use std::io::Write;

#[cfg(test)]
mod integration_tests {
    use super::*;

    fn create_test_python_file(content: &str) -> NamedTempFile {
        let mut temp_file = NamedTempFile::with_suffix(".py").expect("Failed to create temp file");
        write!(temp_file, "{}", content).expect("Failed to write to temp file");
        temp_file
    }

    fn create_test_rules_file(content: &str) -> NamedTempFile {
        let mut temp_file = NamedTempFile::with_suffix(".ron").expect("Failed to create temp file");
        write!(temp_file, "{}", content).expect("Failed to write to temp file");
        temp_file
    }

    #[test]
    fn test_single_pattern_rule_scanning() {
        // Create test Python file with clipboard access
        let python_content = r#"
import pyperclip

def copy_data():
    pyperclip.copy("sensitive data")
    return True

def paste_data():
    data = pyperclip.paste()
    return data
"#;
        let _python_file = create_test_python_file(python_content);

        // Create rules with single patterns
        let rules_content = r#"{
            malware_detection: Some([
                (
                    pattern: "pyperclip.copy",
                    finding_type: Some("clipboard_access"),
                    severity: Some("medium"),
                    conditions: None,
                    file_types: Some((
                        extensions: [".py"],
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
                (
                    pattern: "pyperclip.paste",
                    finding_type: Some("clipboard_access"),
                    severity: Some("medium"),
                    conditions: None,
                    file_types: Some((
                        extensions: [".py"],
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]),
        }"#;
        let rules_file = create_test_rules_file(rules_content);

        // Load and validate rules
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 2);

        // Validate each rule
        for rule in &malware_rules {
            assert!(validate_rule_patterns(rule).is_ok());
        }

        // Test pattern matching
        assert!(rule_matches_pattern(&malware_rules[0], "pyperclip.copy"));
        assert!(!rule_matches_pattern(&malware_rules[0], "pyperclip.paste"));
        assert!(rule_matches_pattern(&malware_rules[1], "pyperclip.paste"));
        assert!(!rule_matches_pattern(&malware_rules[1], "pyperclip.copy"));
    }

    #[test]
    fn test_multiple_patterns_rule_scanning() {
        // Create test Python file with various clipboard operations
        let python_content = r#"
import pyperclip
import pandas as pd
import tkinter as tk

def test_clipboard_operations():
    # Various clipboard access patterns
    pyperclip.copy("data")
    data = pyperclip.paste()
    
    df = pd.DataFrame({"col": [1, 2, 3]})
    df.to_clipboard()
    
    root = tk.Tk()
    root.clipboard_append("text")
    
    # Non-matching function
    print("safe operation")
"#;
        let _python_file = create_test_python_file(python_content);

        // Create rules with multiple patterns
        let rules_content = r#"{
            malware_detection: Some([
                (
                    patterns: [
                        "pyperclip.copy",
                        "pyperclip.paste",
                        "*.to_clipboard",
                        "*.clipboard_append",
                    ],
                    finding_type: Some("clipboard_access"),
                    severity: Some("medium"),
                    confidence: Some("high"),
                    conditions: None,
                    file_types: Some((
                        extensions: [".py"],
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]),
        }"#;
        let rules_file = create_test_rules_file(rules_content);

        // Load and validate rules
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 1);

        let rule = &malware_rules[0];
        assert!(validate_rule_patterns(rule).is_ok());

        // Test that all patterns match
        assert!(rule_matches_pattern(rule, "pyperclip.copy"));
        assert!(rule_matches_pattern(rule, "pyperclip.paste"));
        assert!(rule_matches_pattern(rule, "df.to_clipboard"));
        assert!(rule_matches_pattern(rule, "root.clipboard_append"));
        
        // Test non-matching patterns
        assert!(!rule_matches_pattern(rule, "print"));
        assert!(!rule_matches_pattern(rule, "clipboard.get"));
    }

    #[test]
    fn test_wildcard_patterns_in_multiple_patterns() {
        // Create test Python file with various suspicious patterns
        let python_content = r#"
import keyboard
import subprocess

def malicious_functions():
    keyboard.hook(callback)
    keyboard.on_press(handler)
    
    subprocess.call("malware.exe")
    subprocess.run("virus.exe.hidden")
    
    # Safe functions
    mouse.click()
    file.txt.read()
"#;
        let _python_file = create_test_python_file(python_content);

        // Create rules with wildcard patterns
        let rules_content = r#"{
            malware_detection: Some([
                (
                    patterns: [
                        "keyboard.*",
                        "*.exe*",
                    ],
                    finding_type: Some("suspicious_activity"),
                    severity: Some("high"),
                    conditions: None,
                    file_types: Some((
                        extensions: [".py"],
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]),
        }"#;
        let rules_file = create_test_rules_file(rules_content);

        // Load and validate rules
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        
        let malware_rules = rules.malware_detection.unwrap();
        let rule = &malware_rules[0];

        // Test wildcard matching
        assert!(rule_matches_pattern(rule, "keyboard.hook"));
        assert!(rule_matches_pattern(rule, "keyboard.on_press"));
        assert!(rule_matches_pattern(rule, "malware.exe"));
        assert!(rule_matches_pattern(rule, "virus.exe.hidden"));
        
        // Test non-matching patterns
        assert!(!rule_matches_pattern(rule, "mouse.click"));
        assert!(!rule_matches_pattern(rule, "file.txt"));
    }

    #[test]
    fn test_rule_validation_integration() {
        // Test various rule validation scenarios
        let test_cases = vec![
            // Valid single pattern
            (r#"{
                malware_detection: Some([
                    (
                        pattern: "test_function",
                        finding_type: Some("test"),
                        conditions: None,
                        file_types: None,
                    ),
                ]),
            }"#, true),
            
            // Valid multiple patterns
            (r#"{
                malware_detection: Some([
                    (
                        patterns: ["test1", "test2"],
                        finding_type: Some("test"),
                        conditions: None,
                        file_types: None,
                    ),
                ]),
            }"#, true),
            
            // Invalid: both pattern and patterns (should parse but fail validation)
            (r#"{
                malware_detection: Some([
                    (
                        pattern: "test",
                        patterns: ["test1", "test2"],
                        finding_type: Some("test"),
                        conditions: None,
                        file_types: None,
                    ),
                ]),
            }"#, false),
        ];

        for (rules_content, should_be_valid) in test_cases {
            let rules_file = create_test_rules_file(rules_content);
            let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
                .expect("Failed to load rules");
            
            if let Some(malware_rules) = rules.malware_detection {
                for rule in &malware_rules {
                    let validation_result = validate_rule_patterns(rule);
                    if should_be_valid {
                        assert!(validation_result.is_ok(), "Rule should be valid: {:?}", rule);
                    } else {
                        assert!(validation_result.is_err(), "Rule should be invalid: {:?}", rule);
                    }
                }
            }
        }
    }

    #[test]
    fn test_file_type_filtering() {
        // Create rules that should only apply to Python files
        let rules_content = r#"{
            malware_detection: Some([
                (
                    pattern: "dangerous_function",
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: Some((
                        extensions: [".py"],
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
                (
                    patterns: ["pattern1", "pattern2"],
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: Some((
                        extensions: [".py", ".pyw"],
                        include_patterns: ["*test*"],
                        exclude_patterns: ["*safe*"],
                    )),
                ),
            ]),
        }"#;
        let rules_file = create_test_rules_file(rules_content);

        // Load rules and verify file type filters
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 2);

        // Check first rule file types
        let file_types1 = malware_rules[0].file_types.as_ref().unwrap();
        assert_eq!(file_types1.extensions, Some(vec![".py".to_string()]));
        assert_eq!(file_types1.include_patterns, None);
        assert_eq!(file_types1.exclude_patterns, None);

        // Check second rule file types
        let file_types2 = malware_rules[1].file_types.as_ref().unwrap();
        assert_eq!(file_types2.extensions, Some(vec![".py".to_string(), ".pyw".to_string()]));
        assert_eq!(file_types2.include_patterns, Some(vec!["*test*".to_string()]));
        assert_eq!(file_types2.exclude_patterns, Some(vec!["*safe*".to_string()]));
    }

    #[test]
    fn test_conditions_with_patterns() {
        // Create rules with conditions that use both single and multiple patterns
        let rules_content = r#"{
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
                            patterns: ["*.exe*", "*.bat*", "*.cmd*"],
                            name: None,
                            not_in: None,
                            parent_type: None,
                        ),
                    ]),
                    file_types: None,
                ),
            ]),
        }"#;
        let rules_file = create_test_rules_file(rules_content);

        // Load and validate rules
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        
        let malware_rules = rules.malware_detection.unwrap();
        let rule = &malware_rules[0];

        // Validate rule structure
        assert!(validate_rule_patterns(rule).is_ok());
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
            "*.cmd*".to_string(),
        ]));
    }

    #[test]
    fn test_real_world_malware_patterns() {
        // Test with realistic malware detection patterns
        let rules_content = r#"{
            malware_detection: Some([
                (
                    patterns: [
                        "*.tk*",
                        "*.ml*",
                        "*.ga*",
                        "*.cf*",
                    ],
                    finding_type: Some("suspicious_domain"),
                    severity: Some("medium"),
                    conditions: None,
                    file_types: Some((
                        extensions: [".py"],
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
                (
                    patterns: [
                        "bit.ly",
                        "tinyurl",
                        "t.co",
                    ],
                    finding_type: Some("url_shortener"),
                    severity: Some("low"),
                    conditions: None,
                    file_types: Some((
                        extensions: [".py"],
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]),
        }"#;
        let rules_file = create_test_rules_file(rules_content);

        // Load rules
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 2);

        // Test suspicious domain patterns
        let domain_rule = &malware_rules[0];
        assert!(rule_matches_pattern(domain_rule, "malicious.tk"));
        assert!(rule_matches_pattern(domain_rule, "bad.ml.site"));
        assert!(rule_matches_pattern(domain_rule, "evil.ga"));
        assert!(rule_matches_pattern(domain_rule, "virus.cf.com"));
        assert!(!rule_matches_pattern(domain_rule, "google.com"));

        // Test URL shortener patterns
        let url_rule = &malware_rules[1];
        assert!(rule_matches_pattern(url_rule, "bit.ly"));
        assert!(rule_matches_pattern(url_rule, "tinyurl"));
        assert!(rule_matches_pattern(url_rule, "t.co"));
        assert!(!rule_matches_pattern(url_rule, "github.com"));
    }
} 