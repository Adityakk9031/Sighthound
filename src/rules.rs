use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Condition {
    #[serde(rename = "type")]
    pub condition_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_in: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rule {
    pub pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Rules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injection_sinks: Option<Vec<Rule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_rules: Option<Vec<Rule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_traversal: Option<Vec<Rule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weak_random: Option<Vec<Rule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardcoded_secrets: Option<Vec<Rule>>,
    #[serde(flatten)]
    pub other: HashMap<String, Vec<Rule>>,
}

impl Rules {
    pub fn load_from_file(rules_file: &str) -> Result<Self> {
        let content = fs::read_to_string(rules_file)
            .context(format!("Failed to read rules file: {}", rules_file))?;
        
        serde_json::from_str(&content).context("Failed to parse rules JSON")
    }
}

pub fn match_pattern(pattern: &str, text: &str) -> bool {
    if pattern.contains('*') {
        // Convert wildcard pattern to regex
        let regex_pattern = pattern.replace('*', ".*");
        if let Ok(regex) = Regex::new(&format!("^{}$", regex_pattern)) {
            return regex.is_match(text);
        }
    } else if pattern.starts_with("regex:") {
        // Direct regex pattern
        let regex_pattern = &pattern[6..];
        if let Ok(regex) = Regex::new(regex_pattern) {
            return regex.is_match(text);
        }
    } else {
        // Exact match
        return pattern == text;
    }
    false
} 