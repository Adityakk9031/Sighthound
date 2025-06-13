use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
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

// Custom deserializer that accepts both [Rule, Rule] and Some([Rule, Rule]) for rule arrays
fn deserialize_rule_vec<'de, D>(deserializer: D) -> Result<Option<Vec<Rule>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct RuleVecVisitor;

    impl<'de> Visitor<'de> for RuleVecVisitor {
        type Value = Option<Vec<Rule>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a vector of rules or Option<Vec<Rule>>")
        }

        // Handle direct array: rules: [Rule, Rule]
        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(item) = seq.next_element()? {
                vec.push(item);
            }
            Ok(if vec.is_empty() { None } else { Some(vec) })
        }

        // Handle option: rules: Some([Rule, Rule])
        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            let vec = Vec::<Rule>::deserialize(deserializer)?;
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

    deserializer.deserialize_any(RuleVecVisitor)
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

// Fast injection pattern checking using language-specific patterns
pub fn check_for_injection_pattern(text: &str, language_support: &dyn LanguageSupport) -> bool {
    language_support.injection_patterns().iter().any(|regex| regex.is_match(text))
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FileTypes {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub extensions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub include_patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
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

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Rules {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_rule_vec")]
    pub injection_sinks: Option<Vec<Rule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_rule_vec")]
    pub crypto_rules: Option<Vec<Rule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_rule_vec")]
    pub path_traversal: Option<Vec<Rule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_rule_vec")]
    pub weak_random: Option<Vec<Rule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_rule_vec")]
    pub hardcoded_secrets: Option<Vec<Rule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_rule_vec")]
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

        println!("📋 Loaded {} rules files: {}", loaded_files.len(), loaded_files.join(", "));

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
            // Merge each category of rules
            Self::merge_rule_category(&mut merged.injection_sinks, rules.injection_sinks);
            Self::merge_rule_category(&mut merged.crypto_rules, rules.crypto_rules);
            Self::merge_rule_category(&mut merged.path_traversal, rules.path_traversal);
            Self::merge_rule_category(&mut merged.weak_random, rules.weak_random);
            Self::merge_rule_category(&mut merged.hardcoded_secrets, rules.hardcoded_secrets);
            Self::merge_rule_category(&mut merged.malware_detection, rules.malware_detection);

            // Merge other dynamic categories
            for (key, rules_vec) in rules.other {
                merged.other.entry(key).or_insert_with(Vec::new).extend(rules_vec);
            }
        }

        Ok(merged)
    }

    /// Helper function to merge a specific rule category
    fn merge_rule_category(target: &mut Option<Vec<Rule>>, source: Option<Vec<Rule>>) {
        if let Some(source_rules) = source {
            if let Some(target_rules) = target {
                target_rules.extend(source_rules);
            } else {
                *target = Some(source_rules);
            }
        }
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

// Check if a rule matches a given text (supports both single and multiple patterns)
pub fn rule_matches_pattern(rule: &Rule, text: &str) -> bool {
    // Handle multiple patterns (new format)
    if let Some(patterns) = &rule.patterns {
        return match_any_pattern(patterns, text);
    }
    
    // Handle single pattern (backward compatibility)
    if let Some(pattern) = &rule.pattern {
        return match_pattern(pattern, text);
    }
    
    // No patterns defined - this shouldn't happen in valid rules
    false
}

// Validate rule has either pattern or patterns (but not both)
pub fn validate_rule_patterns(rule: &Rule) -> Result<(), String> {
    match (&rule.pattern, &rule.patterns) {
        (Some(_), Some(_)) => Err("Rule cannot have both 'pattern' and 'patterns' fields".to_string()),
        (None, None) => Err("Rule must have either 'pattern' or 'patterns' field".to_string()),
        (Some(pattern), None) => {
            if pattern.is_empty() {
                Err("Pattern cannot be empty".to_string())
            } else {
                Ok(())
            }
        },
        (None, Some(patterns)) => {
            if patterns.is_empty() {
                Err("Patterns array cannot be empty".to_string())
            } else if patterns.iter().any(|p| p.is_empty()) {
                Err("No pattern in patterns array can be empty".to_string())
            } else {
                Ok(())
            }
        }
    }
}

// Check if a node represents a literal value (reduced false positive risk)
pub fn is_literal_node(node: &tree_sitter::Node) -> bool {
    match node.kind() {
        "integer" | "float" | "true" | "false" | "null" | "none" => true,
        "string" | "string_literal" | "template_string" => {
            // For strings, we need to check if they contain dynamic content
            // This is a basic check - in practice, we should examine the string content
            // to see if it contains format specifiers, interpolation, etc.
            false  // Treat all strings as potentially dynamic for injection analysis
        },
        _ => false,
    }
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

// Custom deserializer that accepts both (struct) and Some((struct)) for FileTypes
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
            formatter.write_str("a FileTypes struct or Option<FileTypes>")
        }

        // Handle direct struct: file_types: (...)
        fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
        where
            A: de::MapAccess<'de>,
        {
            let file_types = FileTypes::deserialize(de::value::MapAccessDeserializer::new(map))?;
            Ok(Some(file_types))
        }

        // Handle option: file_types: Some((...))
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