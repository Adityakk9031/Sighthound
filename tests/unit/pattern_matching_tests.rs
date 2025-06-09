use find_vulns::rules::{Rule, match_pattern, match_any_pattern, rule_matches_pattern, validate_rule_patterns};

#[cfg(test)]
mod pattern_matching_tests {
    use super::*;

    #[test]
    fn test_exact_pattern_matching() {
        // Test exact string matching
        assert!(match_pattern("print", "print"));
        assert!(match_pattern("os.system", "os.system"));
        assert!(!match_pattern("print", "printf"));
        assert!(!match_pattern("os.system", "os.path"));
    }

    #[test]
    fn test_wildcard_pattern_matching() {
        // Test wildcard patterns
        assert!(match_pattern("*.exe", "malware.exe"));
        assert!(match_pattern("*.exe", "file.exe"));
        assert!(!match_pattern("*.exe", "file.txt"));
        
        // Test patterns with wildcards at beginning
        assert!(match_pattern("*password*", "get_password_hash"));
        assert!(match_pattern("*password*", "password"));
        assert!(match_pattern("*password*", "my_password_file"));
        assert!(!match_pattern("*password*", "get_user_name"));
        
        // Test multiple wildcards
        assert!(match_pattern("*test*.py", "my_test_file.py"));
        assert!(match_pattern("*test*.py", "test.py"));
        assert!(!match_pattern("*test*.py", "file.txt"));
    }

    #[test]
    fn test_regex_pattern_matching() {
        // Test basic regex patterns that should work
        assert!(match_pattern("regex:^[a-z]+$", "hello"));
        assert!(!match_pattern("regex:^[a-z]+$", "Hello"));
        assert!(match_pattern("regex:\\d+", "test123"));
        assert!(!match_pattern("regex:\\d+", "test"));
        
        // Test simple patterns
        assert!(match_pattern("regex:eval", "eval"));
        assert!(!match_pattern("regex:^eval$", "evaluate"));
    }

    #[test]
    fn test_edge_cases() {
        // Test empty strings
        assert!(match_pattern("", ""));
        assert!(!match_pattern("test", ""));
        assert!(!match_pattern("", "test"));
        
        // Test special characters
        assert!(match_pattern("test.func", "test.func"));
        assert!(match_pattern("test[0]", "test[0]"));
        assert!(match_pattern("test()", "test()"));
        
        // Test case sensitivity
        assert!(!match_pattern("Print", "print"));
        assert!(match_pattern("print", "print"));
    }

    #[test]
    fn test_match_any_pattern() {
        let patterns = vec![
            "print".to_string(),
            "os.system".to_string(),
            "*.exe".to_string(),
        ];
        
        // Test matching different patterns
        assert!(match_any_pattern(&patterns, "print"));
        assert!(match_any_pattern(&patterns, "os.system"));
        assert!(match_any_pattern(&patterns, "malware.exe"));
        
        // Test non-matching
        assert!(!match_any_pattern(&patterns, "os.path"));
        assert!(!match_any_pattern(&patterns, "file.txt"));
        
        // Test empty patterns array
        let empty_patterns: Vec<String> = vec![];
        assert!(!match_any_pattern(&empty_patterns, "anything"));
    }

    #[test]
    fn test_single_pattern_rule() {
        // Create a rule with single pattern
        let rule = Rule {
            pattern: Some("pyperclip.paste".to_string()),
            patterns: None,
            finding_type: Some("clipboard_access".to_string()),
            conditions: None,
            file_types: None,
            severity: None,
            confidence: None,
            sanitizers: None,
        };
        
        // Test matching
        assert!(rule_matches_pattern(&rule, "pyperclip.paste"));
        assert!(!rule_matches_pattern(&rule, "pyperclip.copy"));
        assert!(!rule_matches_pattern(&rule, "clipboard.get"));
    }

    #[test]
    fn test_multiple_patterns_rule() {
        // Create a rule with multiple patterns
        let rule = Rule {
            pattern: None,
            patterns: Some(vec![
                "pyperclip.paste".to_string(),
                "pyperclip.copy".to_string(),
                "*.to_clipboard".to_string(),
                "win32clipboard".to_string(),
            ]),
            finding_type: Some("clipboard_access".to_string()),
            conditions: None,
            file_types: None,
            severity: None,
            confidence: None,
            sanitizers: None,
        };
        
        // Test all patterns match
        assert!(rule_matches_pattern(&rule, "pyperclip.paste"));
        assert!(rule_matches_pattern(&rule, "pyperclip.copy"));
        assert!(rule_matches_pattern(&rule, "df.to_clipboard"));
        assert!(rule_matches_pattern(&rule, "win32clipboard"));
        
        // Test non-matching
        assert!(!rule_matches_pattern(&rule, "clipboard.get"));
        assert!(!rule_matches_pattern(&rule, "print"));
    }

    #[test]
    fn test_wildcard_patterns_in_multiple_patterns() {
        let rule = Rule {
            pattern: None,
            patterns: Some(vec![
                "*.tk*".to_string(),
                "*.exe*".to_string(),
                "keyboard.*".to_string(),
            ]),
            finding_type: Some("suspicious".to_string()),
            conditions: None,
            file_types: None,
            severity: None,
            confidence: None,
            sanitizers: None,
        };
        
        // Test wildcard matching
        assert!(rule_matches_pattern(&rule, "malicious.tk"));
        assert!(rule_matches_pattern(&rule, "bad.tk.com"));
        assert!(rule_matches_pattern(&rule, "virus.exe"));
        assert!(rule_matches_pattern(&rule, "malware.exe.file"));
        assert!(rule_matches_pattern(&rule, "keyboard.hook"));
        assert!(rule_matches_pattern(&rule, "keyboard.listener"));
        
        // Test non-matching
        assert!(!rule_matches_pattern(&rule, "google.com"));
        assert!(!rule_matches_pattern(&rule, "file.txt"));
        assert!(!rule_matches_pattern(&rule, "mouse.click"));
    }

    #[test]
    fn test_rule_validation() {
        // Valid single pattern rule
        let valid_single = Rule {
            pattern: Some("test".to_string()),
            patterns: None,
            finding_type: None,
            conditions: None,
            file_types: None,
            severity: None,
            confidence: None,
            sanitizers: None,
        };
        assert!(validate_rule_patterns(&valid_single).is_ok());
        
        // Valid multiple patterns rule
        let valid_multiple = Rule {
            pattern: None,
            patterns: Some(vec!["test1".to_string(), "test2".to_string()]),
            finding_type: None,
            conditions: None,
            file_types: None,
            severity: None,
            confidence: None,
            sanitizers: None,
        };
        assert!(validate_rule_patterns(&valid_multiple).is_ok());
        
        // Invalid: both pattern and patterns
        let invalid_both = Rule {
            pattern: Some("test".to_string()),
            patterns: Some(vec!["test1".to_string()]),
            finding_type: None,
            conditions: None,
            file_types: None,
            severity: None,
            confidence: None,
            sanitizers: None,
        };
        assert!(validate_rule_patterns(&invalid_both).is_err());
        
        // Invalid: neither pattern nor patterns
        let invalid_neither = Rule {
            pattern: None,
            patterns: None,
            finding_type: None,
            conditions: None,
            file_types: None,
            severity: None,
            confidence: None,
            sanitizers: None,
        };
        assert!(validate_rule_patterns(&invalid_neither).is_err());
        
        // Invalid: empty pattern
        let invalid_empty_pattern = Rule {
            pattern: Some("".to_string()),
            patterns: None,
            finding_type: None,
            conditions: None,
            file_types: None,
            severity: None,
            confidence: None,
            sanitizers: None,
        };
        assert!(validate_rule_patterns(&invalid_empty_pattern).is_err());
        
        // Invalid: empty patterns array
        let invalid_empty_patterns = Rule {
            pattern: None,
            patterns: Some(vec![]),
            finding_type: None,
            conditions: None,
            file_types: None,
            severity: None,
            confidence: None,
            sanitizers: None,
        };
        assert!(validate_rule_patterns(&invalid_empty_patterns).is_err());
        
        // Invalid: patterns array with empty string
        let invalid_empty_in_patterns = Rule {
            pattern: None,
            patterns: Some(vec!["test".to_string(), "".to_string()]),
            finding_type: None,
            conditions: None,
            file_types: None,
            severity: None,
            confidence: None,
            sanitizers: None,
        };
        assert!(validate_rule_patterns(&invalid_empty_in_patterns).is_err());
    }

    #[test]
    fn test_complex_real_world_patterns() {
        // Test real-world vulnerability patterns
        let sql_injection_patterns = vec![
            "execute".to_string(),
            "*.execute*".to_string(),
            "cursor.execute".to_string(),
            "db.execute".to_string(),
        ];
        
        // Should match SQL injection patterns
        assert!(match_any_pattern(&sql_injection_patterns, "execute"));
        assert!(match_any_pattern(&sql_injection_patterns, "cursor.execute"));
        assert!(match_any_pattern(&sql_injection_patterns, "db.execute"));
        assert!(match_any_pattern(&sql_injection_patterns, "conn.execute_query"));
        
        // Should not match safe patterns
        assert!(!match_any_pattern(&sql_injection_patterns, "executed"));
        assert!(!match_any_pattern(&sql_injection_patterns, "executor"));
        
        // Test command injection patterns
        let command_injection_patterns = vec![
            "os.system".to_string(),
            "subprocess.*".to_string(),
            "*.Popen".to_string(),
            "shell=True".to_string(),
        ];
        
        assert!(match_any_pattern(&command_injection_patterns, "os.system"));
        assert!(match_any_pattern(&command_injection_patterns, "subprocess.call"));
        assert!(match_any_pattern(&command_injection_patterns, "subprocess.Popen"));
        assert!(match_any_pattern(&command_injection_patterns, "shell=True"));
        
        // Test crypto patterns
        let crypto_patterns = vec![
            "*MD5*".to_string(),
            "*SHA1*".to_string(),
            "*.md5*".to_string(),
            "hashlib.md5".to_string(),
        ];
        
        assert!(match_any_pattern(&crypto_patterns, "hashlib.MD5"));
        assert!(match_any_pattern(&crypto_patterns, "crypto.SHA1"));
        assert!(match_any_pattern(&crypto_patterns, "file.md5"));
        assert!(match_any_pattern(&crypto_patterns, "hashlib.md5"));
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_pattern_matching_performance() {
        let patterns = vec![
            "print".to_string(),
            "*.exe".to_string(),
            "regex:^[a-z]+$".to_string(),
            "os.system".to_string(),
            "subprocess.*".to_string(),
        ];
        
        let test_strings = vec![
            "print", "malware.exe", "hello", "os.system", "subprocess.call",
            "safe_function", "file.txt", "HELLO", "os.path", "process.run",
        ];
        
        let start = Instant::now();
        
        // Run pattern matching many times
        for _ in 0..1000 {
            for test_str in &test_strings {
                for pattern in &patterns {
                    match_pattern(pattern, test_str);
                }
            }
        }
        
        let duration = start.elapsed();
        println!("Pattern matching 50,000 times took: {:?}", duration);
        
        // Performance should be reasonable (less than 30 seconds for this test)
        assert!(duration.as_secs() < 30, "Pattern matching too slow: {:?}", duration);
    }

    #[test]
    fn test_multiple_patterns_performance() {
        let rule = Rule {
            pattern: None,
            patterns: Some(vec![
                "print".to_string(),
                "*.exe".to_string(),
                "os.system".to_string(),
                "subprocess.*".to_string(),
                "*password*".to_string(),
                "regex:^[a-z]+$".to_string(),
                "eval".to_string(),
                "exec".to_string(),
                "*.dll".to_string(),
                "malloc".to_string(),
            ]),
            finding_type: None,
            conditions: None,
            file_types: None,
            severity: None,
            confidence: None,
            sanitizers: None,
        };
        
        let test_strings = vec![
            "print", "malware.exe", "os.system", "subprocess.call", "get_password",
            "hello", "eval", "exec", "library.dll", "malloc",
        ];
        
        let start = Instant::now();
        
        // Test rule matching performance
        for _ in 0..1000 {
            for test_str in &test_strings {
                rule_matches_pattern(&rule, test_str);
            }
        }
        
        let duration = start.elapsed();
        println!("Multiple pattern rule matching 10,000 times took: {:?}", duration);
        
        // Should be efficient even with multiple patterns (less than 30 seconds)
        assert!(duration.as_secs() < 30, "Multiple pattern matching too slow: {:?}", duration);
    }
} 