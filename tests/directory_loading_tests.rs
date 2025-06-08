use find_vulns::rules::Rules;
use tempfile::TempDir;
use std::fs;

#[cfg(test)]
mod directory_loading_tests {
    use super::*;

    #[test]
    fn test_load_from_single_file() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let file_path = temp_dir.path().join("test_rules.ron");
        
        let ron_content = r#"{
            malware_detection: Some([
                (
                    pattern: "test_pattern",
                    finding_type: Some("test_type"),
                    conditions: None,
                    file_types: Some((
                        extensions: [".py"],
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]),
        }"#;
        
        fs::write(&file_path, ron_content).expect("Failed to write test file");
        
        let rules = Rules::load_from_path(file_path.to_str().unwrap())
            .expect("Failed to load rules from single file");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 1);
        assert_eq!(malware_rules[0].pattern, Some("test_pattern".to_string()));
        assert_eq!(malware_rules[0].finding_type, Some("test_type".to_string()));
    }

    #[test]
    fn test_load_from_directory() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        
        // Create first rules file
        let file1_path = temp_dir.path().join("rules1.ron");
        let ron_content1 = r#"{
            malware_detection: Some([
                (
                    pattern: "pattern1",
                    finding_type: Some("type1"),
                    conditions: None,
                    file_types: None,
                ),
            ]),
            injection_sinks: Some([
                (
                    pattern: "sql_inject",
                    finding_type: Some("sql_injection"),
                    conditions: None,
                    file_types: None,
                ),
            ]),
        }"#;
        fs::write(&file1_path, ron_content1).expect("Failed to write test file 1");
        
        // Create second rules file
        let file2_path = temp_dir.path().join("rules2.ron");
        let ron_content2 = r#"{
            malware_detection: Some([
                (
                    patterns: ["pattern2", "pattern3"],
                    finding_type: Some("type2"),
                    conditions: None,
                    file_types: None,
                ),
            ]),
            crypto_rules: Some([
                (
                    pattern: "weak_crypto",
                    finding_type: Some("crypto_issue"),
                    conditions: None,
                    file_types: None,
                ),
            ]),
        }"#;
        fs::write(&file2_path, ron_content2).expect("Failed to write test file 2");
        
        // Create a non-rules file (should be ignored)
        let text_file_path = temp_dir.path().join("readme.txt");
        fs::write(&text_file_path, "This should be ignored").expect("Failed to write text file");
        
        let rules = Rules::load_from_path(temp_dir.path().to_str().unwrap())
            .expect("Failed to load rules from directory");
        
        // Check malware_detection rules were merged
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 2);
        
        // Check injection_sinks rules
        let injection_rules = rules.injection_sinks.unwrap();
        assert_eq!(injection_rules.len(), 1);
        assert_eq!(injection_rules[0].pattern, Some("sql_inject".to_string()));
        
        // Check crypto_rules
        let crypto_rules = rules.crypto_rules.unwrap();
        assert_eq!(crypto_rules.len(), 1);
        assert_eq!(crypto_rules[0].pattern, Some("weak_crypto".to_string()));
    }

    #[test]
    fn test_load_from_directory_with_json() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        
        // Create RON file
        let ron_file_path = temp_dir.path().join("rules.ron");
        let ron_content = r#"{
            malware_detection: Some([
                (
                    pattern: "ron_pattern",
                    finding_type: Some("ron_type"),
                    conditions: None,
                    file_types: None,
                ),
            ]),
        }"#;
        fs::write(&ron_file_path, ron_content).expect("Failed to write RON file");
        
        // Create JSON file
        let json_file_path = temp_dir.path().join("rules.json");
        let json_content = r#"{
            "malware_detection": [
                {
                    "pattern": "json_pattern",
                    "finding_type": "json_type",
                    "conditions": null,
                    "file_types": null
                }
            ]
        }"#;
        fs::write(&json_file_path, json_content).expect("Failed to write JSON file");
        
        let rules = Rules::load_from_path(temp_dir.path().to_str().unwrap())
            .expect("Failed to load rules from directory");
        
        let malware_rules = rules.malware_detection.unwrap();
        assert_eq!(malware_rules.len(), 2);
        
        let patterns: Vec<&str> = malware_rules.iter()
            .filter_map(|r| r.pattern.as_deref())
            .collect();
        assert!(patterns.contains(&"ron_pattern"));
        assert!(patterns.contains(&"json_pattern"));
    }

    #[test]
    fn test_load_from_empty_directory() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        
        let result = Rules::load_from_path(temp_dir.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No valid rules files found"));
    }

    #[test]
    fn test_load_from_nonexistent_path() {
        let result = Rules::load_from_path("/nonexistent/path");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("neither a file nor a directory"));
    }

    #[test]
    fn test_merge_rules() {
        let rules1 = Rules {
            malware_detection: Some(vec![]),
            injection_sinks: Some(vec![]),
            ..Rules::default()
        };
        
        let rules2 = Rules {
            malware_detection: Some(vec![]),
            crypto_rules: Some(vec![]),
            ..Rules::default()
        };
        
        let merged = Rules::merge_rules(vec![rules1, rules2])
            .expect("Failed to merge rules");
        
        assert!(merged.malware_detection.is_some());
        assert!(merged.injection_sinks.is_some());
        assert!(merged.crypto_rules.is_some());
        assert!(merged.path_traversal.is_none());
    }
} 