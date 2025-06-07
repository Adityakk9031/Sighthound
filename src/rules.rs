use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use crate::language::LanguageSupport;

// Fast injection pattern checking using language-specific patterns
pub fn check_for_injection_pattern(text: &str, language_support: &dyn LanguageSupport) -> bool {
    language_support.injection_patterns().iter().any(|regex| regex.is_match(text))
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FileTypeFilter {
    pub extensions: Vec<String>,
    pub include_patterns: Option<Vec<String>>,
    pub exclude_patterns: Option<Vec<String>>,
}

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
    // Enhanced fields for better tree-sitter integration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_type: Option<String>,                     // Expected AST node type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argument_position: Option<usize>,              // Specific argument index
    #[serde(skip_serializing_if = "Option::is_none")]
    pub within_lines: Option<usize>,                   // Distance constraint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patterns: Option<Vec<String>>,                 // Multiple patterns
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ancestor_types: Option<Vec<String>>,           // Required ancestor node types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_siblings: Option<bool>,                  // Check sibling nodes
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rule {
    pub pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_types: Option<FileTypeFilter>,
    // Enhanced fields for better analysis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,                      // Critical, High, Medium, Low
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,                    // High, Medium, Low
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitizers: Option<Vec<String>>,              // Known sanitization functions
}

#[derive(Debug, Deserialize, Serialize, Clone)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malware_detection: Option<Vec<Rule>>,
    #[serde(flatten)]
    pub other: HashMap<String, Vec<Rule>>,
}

impl Rules {
    pub fn load_from_file(rules_file: &str) -> Result<Self> {
        let content = fs::read_to_string(rules_file)
            .context(format!("Failed to read rules file: {}", rules_file))?;
        
        let path = Path::new(rules_file);
        let extension = path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        match extension.as_str() {
            "ron" => {
                ron::from_str(&content).context("Failed to parse rules RON")
            },
            "json" | _ => {
                serde_json::from_str(&content).context("Failed to parse rules JSON")
            }
        }
    }

    pub fn save_to_file(&self, rules_file: &str) -> Result<()> {
        let path = Path::new(rules_file);
        let extension = path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        let content = match extension.as_str() {
            "ron" => {
                // Use basic pretty config without struct names
                let config = ron::ser::PrettyConfig::new()
                    .struct_names(false)
                    .enumerate_arrays(false)
                    .compact_arrays(false);
                ron::ser::to_string_pretty(self, config)
                    .context("Failed to serialize rules to RON")?
            },
            "json" | _ => {
                serde_json::to_string_pretty(self)
                    .context("Failed to serialize rules to JSON")?
            }
        };

        fs::write(rules_file, content)
            .context(format!("Failed to write rules file: {}", rules_file))
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

// Enhanced pattern matching with multiple patterns
pub fn match_any_pattern(patterns: &[String], text: &str) -> bool {
    patterns.iter().any(|pattern| match_pattern(pattern, text))
}

// Check if a node represents a literal value (reduced false positive risk)
pub fn is_literal_node(node: &tree_sitter::Node) -> bool {
    matches!(node.kind(), "string" | "integer" | "float" | "true" | "false" | "null" | "none")
}

// Check if a node is in a protective context
pub fn is_in_protective_context(node: &tree_sitter::Node) -> bool {
    let mut current = node.parent();
    let mut depth = 0;
    
    while let Some(parent) = current {
        // Limit search depth to avoid performance issues
        if depth > 10 {
            break;
        }
        
        match parent.kind() {
            // Protective structures that reduce vulnerability likelihood
            "try_statement" | "except_clause" | "if_statement" | 
            "with_statement" | "function_definition" => {
                // Check if this is input validation or error handling
                return true;
            }
            _ => {}
        }
        
        current = parent.parent();
        depth += 1;
    }
    
    false
} 