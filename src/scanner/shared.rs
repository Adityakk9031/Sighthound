use crate::language::LanguageSupport;
use crate::rules::{Rule, Rules, match_pattern, rule_matches_pattern, check_for_injection_pattern, is_literal_node, is_in_protective_context};
use crate::parser::{get_node_text, traverse_calls_only};
use super::types::Finding;
use super::utils::rule_applies_to_file;
use super::conditions::check_ast_conditions;

/// Shared functionality for vulnerability scanning
pub struct ScanningLogic;

impl ScanningLogic {
    /// Check if rules have any patterns matching the function name (fast pre-filter)
    pub fn has_matching_rules(rules: &Rules, func_name: &str) -> bool {
        let rule_categories = [
            &rules.injection_sinks,
            &rules.crypto_rules,
            &rules.path_traversal,
            &rules.weak_random,
            &rules.hardcoded_secrets,
            &rules.malware_detection,
        ];

        for category in &rule_categories {
            if let Some(rules_vec) = category {
                if rules_vec.iter().any(|rule| rule_matches_pattern(rule, func_name)) {
                    return true;
                }
            }
        }

        for rules_vec in rules.other.values() {
            if rules_vec.iter().any(|rule| rule_matches_pattern(rule, func_name)) {
                return true;
            }
        }

        false
    }

    /// Get all rules from a Rules struct as a flat vector
    pub fn get_all_rules(rules: &Rules) -> Vec<Rule> {
        let mut all_rules = Vec::new();
        
        if let Some(rules_vec) = &rules.injection_sinks {
            all_rules.extend(rules_vec.iter().cloned());
        }
        if let Some(rules_vec) = &rules.crypto_rules {
            all_rules.extend(rules_vec.iter().cloned());
        }
        if let Some(rules_vec) = &rules.path_traversal {
            all_rules.extend(rules_vec.iter().cloned());
        }
        if let Some(rules_vec) = &rules.weak_random {
            all_rules.extend(rules_vec.iter().cloned());
        }
        if let Some(rules_vec) = &rules.hardcoded_secrets {
            all_rules.extend(rules_vec.iter().cloned());
        }
        if let Some(rules_vec) = &rules.malware_detection {
            all_rules.extend(rules_vec.iter().cloned());
        }
        
        for rules_vec in rules.other.values() {
            all_rules.extend(rules_vec.iter().cloned());
        }
        
        all_rules
    }

    /// Count total number of rules across all categories
    pub fn count_total_rules(rules: &Rules) -> usize {
        let mut count = 0;
        
        if let Some(rules_vec) = &rules.injection_sinks { count += rules_vec.len(); }
        if let Some(rules_vec) = &rules.crypto_rules { count += rules_vec.len(); }
        if let Some(rules_vec) = &rules.path_traversal { count += rules_vec.len(); }
        if let Some(rules_vec) = &rules.weak_random { count += rules_vec.len(); }
        if let Some(rules_vec) = &rules.hardcoded_secrets { count += rules_vec.len(); }
        if let Some(rules_vec) = &rules.malware_detection { count += rules_vec.len(); }
        
        for rules_vec in rules.other.values() {
            count += rules_vec.len();
        }
        
        count
    }

    /// Check if a node has injection patterns in its arguments
    pub fn has_injection_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        language_support: &dyn LanguageSupport,
    ) -> bool {
        if let Some(args_node) = language_support.get_arguments_node(node) {
            for i in 0..args_node.named_child_count() {
                if let Some(arg) = args_node.named_child(i) {
                    // Skip if argument is a literal (low risk)
                    if is_literal_node(&arg) {
                        continue;
                    }
                    
                    let arg_text = get_node_text(&arg, source);
                    if check_for_injection_pattern(&arg_text, language_support) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check for sanitization patterns in node or context
    pub fn check_for_sanitization(
        node: &tree_sitter::Node,
        source: &[u8],
        sanitizers: &[String],
    ) -> bool {
        // Check if any arguments contain sanitization calls
        let node_text = get_node_text(node, source);
        for sanitizer in sanitizers {
            if match_pattern(sanitizer, &node_text) {
                return true;
            }
        }
        
        // Also check surrounding context for sanitization
        Self::check_context_for_sanitization(node, source, sanitizers)
    }

    /// Check surrounding context for sanitization patterns
    fn check_context_for_sanitization(
        node: &tree_sitter::Node,
        source: &[u8],
        sanitizers: &[String],
    ) -> bool {
        // Look at previous statements in the same scope for sanitization
        if let Some(parent) = node.parent() {
            let mut cursor = parent.walk();
            if cursor.goto_first_child() {
                loop {
                    let sibling = cursor.node();
                    
                    // If we've reached our node, stop looking
                    if sibling == *node {
                        break;
                    }
                    
                    // Check if this previous statement contains sanitization
                    let sibling_text = get_node_text(&sibling, source);
                    for sanitizer in sanitizers {
                        if match_pattern(sanitizer, &sibling_text) {
                            return true;
                        }
                    }
                    
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
        
        false
    }

    /// Determine if a finding should be reported based on confidence and context
    pub fn should_report_finding(
        node: &tree_sitter::Node,
        source: &[u8],
        rule: &Rule,
    ) -> bool {
        // Apply confidence-based filtering
        let confidence = rule.confidence.as_deref().unwrap_or("medium");
        
        match confidence {
            "low" => {
                // For low confidence rules, be more strict
                !is_in_protective_context(node) && !Self::has_obvious_guards(node, source)
            }
            "medium" => {
                // For medium confidence, apply moderate filtering
                !Self::has_obvious_guards(node, source)
            }
            "high" => {
                // High confidence rules report more freely
                true
            }
            _ => true
        }
    }

    /// Check for obvious guard patterns around the node
    fn has_obvious_guards(node: &tree_sitter::Node, source: &[u8]) -> bool {
        // Look for common guard patterns in the immediate vicinity
        let guard_patterns = [
            "if.*valid", "if.*check", "if.*safe", "if.*sanitize",
            "try:", "except:", "validate", "escape", "quote"
        ];
        
        // Check preceding and following statements
        if let Some(parent) = node.parent() {
            let parent_text = get_node_text(&parent, source);
            
            for pattern in &guard_patterns {
                if match_pattern(pattern, &parent_text.to_lowercase()) {
                    return true;
                }
            }
        }
        
        false
    }

    /// Add metadata to findings based on rule properties
    pub fn add_finding_metadata(finding: &mut Finding, rule: &Rule, node: &tree_sitter::Node) {
        let confidence = rule.confidence.as_deref().unwrap_or("medium");
        
        // Only modify finding_type for low confidence findings to help users prioritize
        if confidence == "low" || (confidence == "medium" && is_in_protective_context(node)) {
            finding.finding_type = format!("{}_low_confidence", finding.finding_type);
        }
    }

    /// Create a finding from scan results
    pub fn create_finding(
        file: &str,
        node: &tree_sitter::Node,
        function: &str,
        finding_type: &str,
        source: &[u8],
        severity: &str,
    ) -> Finding {
        Finding {
            file: file.to_string(),
            line: node.start_position().row + 1,
            function: function.to_string(),
            finding_type: finding_type.to_string(),
            code: get_node_text(node, source).trim().to_string(),
            severity: severity.to_string(),
        }
    }

    /// Main rule checking logic - checks a single rule against a node
    pub fn check_rule_against_node(
        rule: &Rule,
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        func_name: &str,
        language_support: &dyn LanguageSupport,
    ) -> Option<Finding> {
        // Check if rule applies to this file first
        if !rule_applies_to_file(rule, filepath) {
            return None;
        }
        
        // Check if function name matches rule pattern
        if !rule_matches_pattern(rule, func_name) {
            return None;
        }
        
        // Check AST conditions if specified
        let conditions = rule.conditions.as_deref().unwrap_or(&[]);
        if !check_ast_conditions(node, source, conditions, language_support) {
            return None;
        }
        
        // Check for sanitization if specified in rule
        if let Some(sanitizers) = &rule.sanitizers {
            if Self::check_for_sanitization(node, source, sanitizers) {
                return None; // Skip this finding if sanitized
            }
        }
        
        // Determine finding type
        let finding_type = rule.finding_type.as_deref().unwrap_or("vulnerability");
        let severity = rule.severity.as_deref().unwrap_or("medium");
        
        // Special handling for injection sinks
        if finding_type == "injection_sinks" || finding_type.contains("injection") {
            // Check if arguments have injection patterns
            let has_injection = Self::has_injection_pattern(node, source, language_support);
            
            if !has_injection {
                // For SQL injection, additionally check if arguments contain user inputs or concat
                if finding_type.contains("sql") {
                    // Check if node text contains "+" or "concat" - common in string concatenation
                    let node_text = get_node_text(node, source).to_lowercase();
                    let contains_concat = node_text.contains("+") || 
                                          node_text.contains("concat") || 
                                          node_text.contains("format");
                    
                    if contains_concat {
                        // Finding continues to be reported
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
        }
        
        // Apply confidence-based filtering
        if !Self::should_report_finding(node, source, rule) {
            return None;
        }
        
        // Create the finding
        let mut finding = Self::create_finding(filepath, node, func_name, finding_type, source, severity);
        Self::add_finding_metadata(&mut finding, rule, node);
        
        Some(finding)
    }

    /// Scan a file with a set of rules - core scanning logic
    pub fn scan_file_with_rules(
        filepath: &str,
        source: &[u8],
        tree: &tree_sitter::Tree,
        rules: &[Rule],
        language_support: &dyn LanguageSupport,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let root_node = tree.root_node();
        
        for node in traverse_calls_only(root_node, language_support) {
            // Skip nodes that are in comments
            if let Some(parent) = node.parent() {
                if parent.kind() == "comment" {
                    continue;
                }
            }
            
            if let Some(func_name) = language_support.get_function_name(&node, source) {
                // Quick pre-filter: only check nodes that have potentially matching rules
                let has_potential_match = rules.iter().any(|rule| rule_matches_pattern(rule, func_name));
                if !has_potential_match {
                    continue;
                }
                
                // Check each rule against this node
                for rule in rules {
                    if let Some(finding) = Self::check_rule_against_node(
                        rule,
                        &node,
                        source,
                        filepath,
                        func_name,
                        language_support,
                    ) {
                        findings.push(finding);
                    }
                }
            }
        }
        
        findings
    }
} 