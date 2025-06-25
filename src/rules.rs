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

// Custom deserializer that accepts both [TaintFlowRule, TaintFlowRule] and Some([TaintFlowRule, TaintFlowRule]) for taint flow arrays
fn deserialize_taint_flows<'de, D>(deserializer: D) -> Result<Option<Vec<TaintFlowRule>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct TaintFlowVecVisitor;

    impl<'de> Visitor<'de> for TaintFlowVecVisitor {
        type Value = Option<Vec<TaintFlowRule>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a vector of taint flow rules or Option<Vec<TaintFlowRule>>")
        }

        // Handle direct array: taint_flows: [TaintFlowRule, TaintFlowRule]
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

        // Handle option: taint_flows: Some([TaintFlowRule, TaintFlowRule])
        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            let vec = Vec::<TaintFlowRule>::deserialize(deserializer)?;
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

    deserializer.deserialize_any(TaintFlowVecVisitor)
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

// Unified Rules structure that handles both pattern matching and taint analysis
#[derive(Debug, Deserialize, Serialize)]
pub struct Rules {
    // Main rules collection - unified approach
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_unified_rules")]
    pub rules: Option<Vec<UnifiedRule>>,
    
    // Legacy support - these will be converted to UnifiedRule internally
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
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_taint_flows")]
    pub taint_flows: Option<Vec<TaintFlowRule>>,
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
            Self::merge_taint_flow_category(&mut merged.taint_flows, rules.taint_flows);

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

    /// Helper function to merge taint flow rules
    fn merge_taint_flow_category(target: &mut Option<Vec<TaintFlowRule>>, source: Option<Vec<TaintFlowRule>>) {
        if let Some(source_flows) = source {
            if let Some(target_flows) = target {
                target_flows.extend(source_flows);
            } else {
                *target = Some(source_flows);
            }
        }
    }
    
    /// Get all rules as a unified collection, converting legacy rules if needed
    pub fn get_unified_rules(&self) -> Vec<UnifiedRule> {
        let mut all_rules = Vec::new();
        
        // Add modern unified rules directly
        if let Some(unified_rules) = &self.rules {
            all_rules.extend(unified_rules.clone());
        }
        
        // Convert legacy rules to unified format
        self.convert_legacy_rules(&mut all_rules);
        
        all_rules
    }
    
    /// Convert legacy rule categories to unified rules
    fn convert_legacy_rules(&self, all_rules: &mut Vec<UnifiedRule>) {
        // Convert injection sinks
        if let Some(rules) = &self.injection_sinks {
            for rule in rules {
                all_rules.push(self.convert_rule_to_unified(rule, "SQL Injection"));
            }
        }
        
        // Convert crypto rules
        if let Some(rules) = &self.crypto_rules {
            for rule in rules {
                all_rules.push(self.convert_rule_to_unified(rule, "Cryptographic Vulnerability"));
            }
        }
        
        // Convert path traversal
        if let Some(rules) = &self.path_traversal {
            for rule in rules {
                all_rules.push(self.convert_rule_to_unified(rule, "Path Traversal"));
            }
        }
        
        // Convert weak random
        if let Some(rules) = &self.weak_random {
            for rule in rules {
                all_rules.push(self.convert_rule_to_unified(rule, "Weak Randomness"));
            }
        }
        
        // Convert hardcoded secrets
        if let Some(rules) = &self.hardcoded_secrets {
            for rule in rules {
                all_rules.push(self.convert_rule_to_unified(rule, "Hardcoded Secret"));
            }
        }
        
        // Convert malware detection
        if let Some(rules) = &self.malware_detection {
            for rule in rules {
                all_rules.push(self.convert_rule_to_unified(rule, "Malware Detection"));
            }
        }
        
        // Convert taint flows
        if let Some(taint_rules) = &self.taint_flows {
            for taint_rule in taint_rules {
                all_rules.push(self.convert_taint_rule_to_unified(taint_rule));
            }
        }
        
        // Convert other categories
        for (category, rules) in &self.other {
            for rule in rules {
                all_rules.push(self.convert_rule_to_unified(rule, category));
            }
        }
    }
    
    /// Convert a legacy Rule to UnifiedRule
    fn convert_rule_to_unified(&self, rule: &Rule, default_finding_type: &str) -> UnifiedRule {
        UnifiedRule {
            id: None,
            name: None,
            description: None,
            mode: "search".to_string(),
            pattern: rule.pattern.clone(),
            patterns: rule.patterns.clone(),
            sources: None,
            sinks: None,
            propagators: None,
            sanitizers: rule.sanitizers.clone(),
            finding_type: rule.finding_type.clone().or_else(|| Some(default_finding_type.to_string())),
            severity: rule.severity.clone(),
            confidence: rule.confidence.clone(),
            file_types: rule.file_types.clone(),
            conditions: rule.conditions.clone(),
            tags: None,
            message: None,
        }
    }
    
    /// Convert a legacy TaintFlowRule to UnifiedRule
    fn convert_taint_rule_to_unified(&self, taint_rule: &TaintFlowRule) -> UnifiedRule {
        UnifiedRule {
            id: None,
            name: taint_rule.flow_name.clone(),
            description: None,
            mode: "taint".to_string(),
            pattern: None,
            patterns: None,
            sources: taint_rule.sources.clone(),
            sinks: taint_rule.sinks.clone(),
            propagators: taint_rule.propagators.clone(),
            sanitizers: taint_rule.sanitizers.clone(),
            finding_type: Some("Taint Flow Vulnerability".to_string()),
            severity: taint_rule.severity.clone(),
            confidence: taint_rule.confidence.clone(),
            file_types: taint_rule.file_types.clone(),
            conditions: None,
            tags: None,
            message: None,
        }
    }
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            rules: None,
            injection_sinks: None,
            crypto_rules: None,
            path_traversal: None,
            weak_random: None,
            hardcoded_secrets: None,
            malware_detection: None,
            taint_flows: None,
            other: HashMap::new(),
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

// Deserializer for unified rules
fn deserialize_unified_rules<'de, D>(deserializer: D) -> Result<Option<Vec<UnifiedRule>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct UnifiedRulesVisitor;

    impl<'de> Visitor<'de> for UnifiedRulesVisitor {
        type Value = Option<Vec<UnifiedRule>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of unified rules")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut rules = Vec::new();
            while let Some(rule) = seq.next_element::<UnifiedRule>()? {
                rules.push(rule);
            }
            Ok(Some(rules))
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_seq(self)
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

    deserializer.deserialize_option(UnifiedRulesVisitor)
}

// Enhanced unified rule structure that supports both pattern matching and taint analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedRule {
    // Rule identification and metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
    pub id: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
    pub name: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
    pub description: Option<String>,
    
    // Analysis mode - determines how the rule is processed
    #[serde(default = "default_search_mode")]
    pub mode: String, // "search" (default) or "taint"
    
    // Pattern matching (used in search mode and as patterns in taint mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_pattern")]
    pub pattern: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub patterns: Option<Vec<String>>,
    
    // Taint analysis fields (used when mode = "taint")
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub sources: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub sinks: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub propagators: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_patterns")]
    pub sanitizers: Option<Vec<String>>,
    
    // Metadata and configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
    pub finding_type: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
    pub severity: Option<String>, // Critical, High, Medium, Low
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
    pub confidence: Option<String>, // High, Medium, Low
    
    // File filtering
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_file_types")]
    pub file_types: Option<FileTypes>,
    
    // Advanced conditions for pattern matching
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    
    // Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_string")]
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
} 