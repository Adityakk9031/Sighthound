use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use std::fs;
use std::path::Path;
use crate::language::LanguageSupport;

// Custom deserializer that accepts both "value" and Some("value") for pattern field
fn deserialize_pattern<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct PatternVisitor;

    impl<'de> Visitor<'de> for PatternVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or Option<String>")
        }

        // Handle direct string: pattern: "value"
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value.to_string()))
        }

        // Handle option: pattern: Some("value") or pattern: None
        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Ok(Some(s))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(PatternVisitor)
}

// Custom deserializer that accepts both ["val1", "val2"] and Some(["val1", "val2"]) for patterns field
fn deserialize_patterns<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct PatternsVisitor;

    impl<'de> Visitor<'de> for PatternsVisitor {
        type Value = Option<Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an array of strings or Option<Vec<String>>")
        }

        // Handle direct array: patterns: ["val1", "val2"]
        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(elem) = seq.next_element()? {
                vec.push(elem);
            }
            Ok(Some(vec))
        }

        // Handle option: patterns: Some(["val1", "val2"]) or patterns: None
        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            let vec = Vec::<String>::deserialize(deserializer)?;
            Ok(Some(vec))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(PatternsVisitor)
}

// Custom deserializer that accepts both "value" and Some("value") for optional string fields
fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct OptionalStringVisitor;

    impl<'de> Visitor<'de> for OptionalStringVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or Option<String>")
        }

        // Handle direct string: field: "value"
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value.to_string()))
        }

        // Handle option: field: Some("value")
        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Ok(Some(s))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(OptionalStringVisitor)
}

// Simple injection pattern checking for basic patterns
pub fn check_for_injection_pattern(text: &str, _language_support: &dyn LanguageSupport) -> bool {
    // Basic injection indicators that are language-agnostic
    let basic_patterns = [
        ";", "&&", "||", "`", "$(",  // Command separators/chaining
        "eval(", "exec(", "system(",  // Dangerous functions  
        "{{", "{%",                   // Template injection
        "javascript:", "data:",       // URL schemes
    ];
    
    basic_patterns.iter().any(|&pattern| text.contains(pattern))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileTypes {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub extensions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub include_patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub exclude_patterns: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Condition {
    #[serde(rename = "type")]
    pub condition_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_pattern")]
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
    pub within_lines: Option<usize>,                   // Distance constraint for proximity checks
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub patterns: Option<Vec<String>>,                 // Multiple patterns
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ancestor_types: Option<Vec<String>>,           // Required ancestor node types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_siblings: Option<bool>,                  // Check sibling nodes for related patterns
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rule {
    // Support both single pattern (backward compatible) and multiple patterns
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_pattern")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
    pub finding_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_file_types")]
    pub file_types: Option<FileTypes>,
    // Enhanced fields for better analysis
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
    pub severity: Option<String>,                      // Critical, High, Medium, Low
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
    pub confidence: Option<String>,                    // High, Medium, Low
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitizers: Option<Vec<String>>,              // Known sanitization functions
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TaintFlowRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
    pub flow_name: Option<String>,
    
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub sources: Option<Vec<String>>,
    
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub sinks: Option<Vec<String>>,
    
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub propagators: Option<Vec<String>>,
    
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub sanitizers: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
    pub severity: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
    pub confidence: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_file_types")]
    pub file_types: Option<FileTypes>,
}



fn deserialize_optional_file_types<'de, D>(deserializer: D) -> Result<Option<FileTypes>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct OptionalFileTypesVisitor;

    impl<'de> Visitor<'de> for OptionalFileTypesVisitor {
        type Value = Option<FileTypes>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("file types object or Option<FileTypes>")
        }

        fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
        where
            A: de::MapAccess<'de>,
        {
            let file_types = FileTypes::deserialize(de::value::MapAccessDeserializer::new(map))?;
            Ok(Some(file_types))
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            let file_types = FileTypes::deserialize(deserializer)?;
            Ok(Some(file_types))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(OptionalFileTypesVisitor)
}

// Enhanced unified rule structure that supports both pattern matching and taint analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedRule {
    // Rule identification and metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub id: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub name: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub description: Option<String>,
    
    // NEW: Category field for organization
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub category: Option<String>,
    
    // Analysis mode - determines how the rule is processed
    #[serde(default = "default_search_mode")]
    pub mode: String, // "search" (default) or "taint"
    
    // Pattern matching (used in search mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub pattern: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub patterns: Option<Vec<String>>,
    
    // Taint analysis fields (used when mode = "taint")
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub sources: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub sinks: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub propagators: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub sanitizers: Option<Vec<String>>,
    
    // Metadata and configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub finding_type: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub severity: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub confidence: Option<String>,
    
    // File filtering
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub file_types: Option<FileTypes>,
    
    // Advanced conditions for pattern matching
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    
    // Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub message: Option<String>,
}

fn default_search_mode() -> String {
    "search".to_string()
}

impl UnifiedRule {
    /// Returns true if this is a taint analysis rule
    pub fn is_taint_rule(&self) -> bool {
        self.mode == "taint"
    }
    
    /// Returns true if this is a search/pattern matching rule
    pub fn is_search_rule(&self) -> bool {
        self.mode == "search" || self.mode.is_empty()
    }
    
    /// Validates that the rule has the required fields for its mode
    pub fn validate(&self) -> Result<(), String> {
        match self.mode.as_str() {
            "search" | "" => {
                if self.pattern.is_none() && self.patterns.is_none() {
                    return Err("Search mode rules must have either 'pattern' or 'patterns'".to_string());
                }
            }
            "taint" => {
                if self.sources.is_none() {
                    return Err("Taint mode rules must have 'sources'".to_string());
                }
                if self.sinks.is_none() {
                    return Err("Taint mode rules must have 'sinks'".to_string());
                }
            }
            _ => {
                return Err(format!("Unsupported rule mode: '{}'. Supported modes: 'search', 'taint'", self.mode));
            }
        }
        Ok(())
    }
    
    /// Gets the effective finding type, with fallback logic
    pub fn get_finding_type(&self) -> String {
        self.finding_type
            .clone()
            .unwrap_or_else(|| {
                if self.is_taint_rule() {
                    "Taint Flow Vulnerability".to_string()
                } else {
                    "Security Vulnerability".to_string()
                }
            })
    }
    
    /// Gets the effective severity with fallback
    pub fn get_severity(&self) -> String {
        self.severity.clone().unwrap_or_else(|| "Medium".to_string())
    }
    
    /// Gets the effective confidence with fallback
    pub fn get_confidence(&self) -> String {
        self.confidence.clone().unwrap_or_else(|| "Medium".to_string())
    }

    /// Gets the category with fallback
    pub fn get_category(&self) -> String {
        self.category.clone().unwrap_or_else(|| "security".to_string())
    }
}

// Simplified Rules structure - only unified rules
#[derive(Debug, Deserialize, Serialize)]
pub struct Rules {
    #[serde(default)]
    pub rules: Vec<UnifiedRule>,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
        }
    }
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
            _ => {
                Err(anyhow::anyhow!("Unsupported file format. Only .ron files are supported for rules."))
            }
        }
    }

    /// Load rules from a file or directory
    /// If path is a file, loads that single RON file
    /// If path is a directory, loads all .ron files and merges them
    pub fn load_from_path(rules_path: &str) -> Result<Self> {
        let path = Path::new(rules_path);
        
        if path.is_file() {
            Self::load_from_file(rules_path)
        } else if path.is_dir() {
            Self::load_from_directory(rules_path)
        } else {
            Err(anyhow::anyhow!("Rules path '{}' is neither a file nor a directory", rules_path))
        }
    }

    /// Load all .ron files from a directory and merge them
    pub fn load_from_directory(rules_dir: &str) -> Result<Self> {
        let dir_path = Path::new(rules_dir);
        
        if !dir_path.is_dir() {
            return Err(anyhow::anyhow!("Path '{}' is not a directory", rules_dir));
        }

        let entries = fs::read_dir(dir_path)
            .context(format!("Failed to read directory: {}", rules_dir))?;

        let mut all_rules = Vec::new();
        let mut loaded_files = Vec::new();

        for entry in entries {
            let entry = entry.context("Failed to read directory entry")?;
            let file_path = entry.path();
            
            // Only process .ron files
            if let Some(extension) = file_path.extension() {
                let ext_str = extension.to_string_lossy().to_lowercase();
                if ext_str == "ron" {
                    let file_path_str = file_path.to_string_lossy();
                    
                    match Self::load_from_file(&file_path_str) {
                        Ok(rules) => {
                            all_rules.push(rules);
                            loaded_files.push(file_path_str.to_string());
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to load rules from {}: {}", file_path_str, e);
                        }
                    }
                }
            }
        }

        if all_rules.is_empty() {
            return Err(anyhow::anyhow!("No valid .ron rules files found in directory: {}", rules_dir));
        }

        // Merge all rules into a single Rules instance
        Self::merge_rules(all_rules)
    }

    /// Merge multiple Rules instances into one
    pub fn merge_rules(rules_list: Vec<Self>) -> Result<Self> {
        if rules_list.is_empty() {
            return Ok(Self::default());
        }

        let mut merged = Self::default();

        for rules in rules_list {
            merged.rules.extend(rules.rules);
        }

        Ok(merged)
    }

    /// Get all search mode rules
    pub fn get_search_rules(&self) -> Vec<&UnifiedRule> {
        self.rules.iter().filter(|rule| rule.is_search_rule()).collect()
    }

    /// Get all taint mode rules
    pub fn get_taint_rules(&self) -> Vec<&UnifiedRule> {
        self.rules.iter().filter(|rule| rule.is_taint_rule()).collect()
    }

    /// Count total number of rules
    pub fn count_rules(&self) -> usize {
        self.rules.len()
    }

    /// Get rules by category
    pub fn get_rules_by_category(&self, category: &str) -> Vec<&UnifiedRule> {
        self.rules.iter().filter(|rule| {
            rule.category.as_ref().map(|c| c == category).unwrap_or(false)
        }).collect()
    }
}

pub fn match_pattern(pattern: &str, text: &str) -> bool {
    if pattern.contains('*') {
        // Convert wildcard pattern to regex
        let regex_pattern = pattern.replace('*', ".*");
        if let Ok(regex) = Regex::new(&format!("^{}$", regex_pattern)) {
            return regex.is_match(text);
        }
    } else if let Some(regex_pattern) = pattern.strip_prefix("regex:") {
        // Direct regex pattern
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

pub fn rule_matches_pattern_unified(rule: &UnifiedRule, text: &str) -> bool {
    if let Some(pattern) = &rule.pattern {
        if match_pattern(pattern, text) {
            return true;
        }
    }
    
    if let Some(patterns) = &rule.patterns {
        for pattern in patterns {
            if match_pattern(pattern, text) {
                return true;
            }
        }
    }
    
    false
}

pub fn validate_unified_rule_patterns(rule: &UnifiedRule) -> Result<(), String> {
    if rule.is_search_rule() {
        if let Some(pattern) = &rule.pattern {
            if pattern.starts_with("regex:") {
                let regex_pattern = &pattern[6..];
                Regex::new(regex_pattern).map_err(|e| format!("Invalid regex pattern '{}': {}", regex_pattern, e))?;
            }
        }
        
        if let Some(patterns) = &rule.patterns {
            for pattern in patterns {
                if pattern.starts_with("regex:") {
                    let regex_pattern = &pattern[6..];
                    Regex::new(regex_pattern).map_err(|e| format!("Invalid regex pattern '{}': {}", regex_pattern, e))?;
                }
            }
        }
    }
    Ok(())
}

pub fn is_literal_node(node: &tree_sitter::Node) -> bool {
    match node.kind() {
        "string" | "string_literal" | "number" | "integer" | "float" | 
        "boolean" | "true" | "false" | "null" | "none" => true,
        _ => false,
    }
}

pub fn is_in_protective_context(node: &tree_sitter::Node) -> bool {
    let mut current = node.parent();
    let mut depth = 0;
    const MAX_DEPTH: usize = 10;
    
    while let Some(parent) = current {
        if depth > MAX_DEPTH {
            break;
        }
        
        match parent.kind() {
            "try_statement" | "except_clause" | "if_statement" | "conditional_expression" => {
                return true;
            }
            "function_definition" | "method_definition" => {
                // Check if function name suggests validation/sanitization
                if let Some(_name_node) = parent.child_by_field_name("name") {
                    // This would need source bytes to extract the actual name
                    // For now, assume protective if in a function
                    return true;
                }
            }
            _ => {}
        }
        
        current = parent.parent();
        depth += 1;
    }
    
    false
} 