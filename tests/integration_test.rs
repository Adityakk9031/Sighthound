use find_vulns::{Rules, VulnerabilityScanner};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_basic_vulnerability_detection() {
    // Create temporary directory with test files
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.py");
    
    fs::write(&test_file, r#"
import os
import subprocess

def vulnerable_function():
    os.system("rm -rf /")  # Command injection
    subprocess.call("echo hello", shell=True)  # Command injection
"#).unwrap();

    // Load rules
    let rules = Rules::load_from_file("rules/python.json").unwrap();
    let mut scanner = VulnerabilityScanner::new("python", rules).unwrap();
    
    // Run scan
    let findings = scanner.find_vulnerabilities(temp_dir.path().to_str().unwrap(), "python").unwrap();
    
    // Should find vulnerabilities
    assert!(!findings.is_empty(), "Should find vulnerabilities in test file");
    
    // Check specific findings
    let has_os_system = findings.iter().any(|f| f.function.contains("os.system"));
    let has_subprocess = findings.iter().any(|f| f.function.contains("subprocess.call"));
    
    assert!(has_os_system, "Should detect os.system vulnerability");
    assert!(has_subprocess, "Should detect subprocess.call vulnerability");
}

#[test]
fn test_no_false_positives() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("safe.py");
    
    fs::write(&test_file, r#"
import os
import subprocess

def safe_function():
    # These should not trigger
    print("hello world")
    x = 1 + 2
    return x
"#).unwrap();

    let rules = Rules::load_from_file("rules/python.json").unwrap();
    let mut scanner = VulnerabilityScanner::new("python", rules).unwrap();
    
    let findings = scanner.find_vulnerabilities(temp_dir.path().to_str().unwrap(), "python").unwrap();
    
    // Should not find any vulnerabilities in safe code
    assert!(findings.is_empty(), "Should not find vulnerabilities in safe code");
} 