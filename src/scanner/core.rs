//! Core vulnerability scanning engine
//! 
//! This module provides the main vulnerability scanning functionality including:
//! - Pattern-based vulnerability detection
//! - Taint flow analysis across single and multiple files
//! - Progress tracking and result reporting

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle, ProgressDrawTarget};
use memmap2::Mmap;
use rayon::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use syntect::easy::HighlightLines;
use syntect::highlighting::{Style, ThemeSet};
use syntect::parsing::SyntaxSet;
use walkdir::WalkDir;

use crate::common::CommonUtils;
use crate::config::filters::SKIP_DIRS;
use crate::models::Finding;
use crate::parser::LanguageParser;
use crate::rules::Rules;

// ============================================================================
// CORE SCANNING ENGINE - Rule matching and vulnerability detection  
// ============================================================================

/// Deduplicates taint rules to prevent cartesian product problems
#[derive(Debug, Clone)]
struct TaintRuleDeduplicator {
    /// Mapping from (source_pattern, sink_pattern) to the rule that should handle it
    rule_mapping: std::collections::HashMap<(String, String), crate::rules::UnifiedRule>,
    /// Consolidated source patterns across all rules
    source_patterns: std::collections::HashSet<String>,
    /// Consolidated sink patterns across all rules
    sink_patterns: std::collections::HashSet<String>,
}

impl TaintRuleDeduplicator {
    /// Create a new deduplicator from a list of taint rules
    fn new(taint_rules: &[&crate::rules::UnifiedRule]) -> Self {
        let mut deduplicator = Self {
            rule_mapping: std::collections::HashMap::new(),
            source_patterns: std::collections::HashSet::new(),
            sink_patterns: std::collections::HashSet::new(),
        };

        // Process each rule and create specific source-sink mappings
        for rule in taint_rules {
            if let (Some(sources), Some(sinks)) = (&rule.sources, &rule.sinks) {
                // Add all patterns to consolidated sets
                for source in sources {
                    deduplicator.source_patterns.insert(source.clone());
                }
                for sink in sinks {
                    deduplicator.sink_patterns.insert(sink.clone());
                }

                // Create specific mappings for this rule's source-sink combinations
                for source in sources {
                    for sink in sinks {
                        let key = (source.clone(), sink.clone());
                        deduplicator.rule_mapping.insert(key, (*rule).clone());
                    }
                }
            }
        }

        deduplicator
    }

    /// Get the specific rule for a source-sink combination
    fn get_rule_for_combination(&self, source_pattern: &str, sink_pattern: &str) -> Option<&crate::rules::UnifiedRule> {
        self.rule_mapping.get(&(source_pattern.to_string(), sink_pattern.to_string()))
    }

    /// Check if a pattern matches any source
    fn matches_source_pattern(&self, text: &str) -> Option<String> {
        for pattern in &self.source_patterns {
            if CommonUtils::matches_taint_pattern(pattern, text) {
                return Some(pattern.clone());
            }
        }
        None
    }

    /// Check if a pattern matches any sink
    fn matches_sink_pattern(&self, text: &str) -> Option<String> {
        for pattern in &self.sink_patterns {
            if CommonUtils::matches_taint_pattern(pattern, text) {
                return Some(pattern.clone());
            }
        }
        None
    }


}

pub struct ScanningLogic;

impl ScanningLogic {
    pub fn check_rule_against_node(
        rule: &crate::rules::UnifiedRule,
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        func_name: &str,
        language_support: &dyn crate::language::LanguageSupport,
    ) -> Option<crate::models::Finding> {
        let pattern_matches = if Self::rule_needs_full_context(rule) {
            let node_text = crate::parser::get_node_text(node, source);
            crate::rules::rule_matches_pattern_unified(rule, &node_text)
        } else {
            crate::rules::rule_matches_pattern_unified(rule, func_name)
        };

        if !pattern_matches {
            return None;
        }

        if !crate::scanner::utils::rule_applies_to_file(rule.file_types.as_ref(), filepath) {
            return None;
        }

        if let Some(conditions) = &rule.conditions {
            if !crate::scanner::conditions::check_ast_conditions(conditions, node, source, language_support) {
                return None;
            }
        }

        if language_support.name() == "javascript" || language_support.name() == "typescript" {
            let node_text = crate::parser::get_node_text(node, source);
            if !Self::should_apply_rule_with_sanitization(rule, &node_text) {
                return None;
            }
        }

        if Self::should_check_injection_patterns(rule) {
            if !Self::has_injection_pattern(node, source, language_support) {
                return None;
            }
        }

        let mut finding = Self::create_finding(
            filepath, node, func_name, &rule.get_finding_type(), source, &rule.get_severity()
        );

        Self::add_finding_metadata(&mut finding, rule, node);

        if let Some(source_info) = Self::detect_source_pattern(node, source, language_support) {
            finding.source_info = Some(source_info);
        }

        if let Some(sink_info) = Self::detect_sink_pattern(node, source, func_name, &rule.get_finding_type()) {
            finding.sink_info = Some(sink_info);
        }

        Some(finding)
    }

    fn rule_needs_full_context(rule: &crate::rules::UnifiedRule) -> bool {
        const CONTEXT_INDICATORS: &[&str] = &[
            "%", "+", "DROP", "DELETE", "UNION", "innerHTML", "outerHTML", "location", 
            "postMessage", "localStorage", "sessionStorage", "console.log", "console.debug",
            "fetch", "axios", "password", "token", "secret", "key", "http://", "="
        ];

        let check_pattern = |pattern: &str| {
            CONTEXT_INDICATORS.iter().any(|indicator| pattern.contains(indicator))
        };

        if let Some(patterns) = &rule.patterns {
            patterns.iter().any(|p| check_pattern(p))
        } else if let Some(pattern) = &rule.pattern {
            check_pattern(pattern)
        } else {
            false
        }
    }

    fn should_check_injection_patterns(rule: &crate::rules::UnifiedRule) -> bool {
        rule.get_category() == "injection"
    }
    pub fn scan_file_with_rules(
        filepath: &str,
        source: &[u8],
        tree: &tree_sitter::Tree,
        rules: &[&crate::rules::UnifiedRule],
        language_support: &dyn crate::language::LanguageSupport,
    ) -> Vec<crate::models::Finding> {
        let mut findings = Vec::new();
        let mut processed_lines = std::collections::HashSet::new();

        let call_nodes: Vec<tree_sitter::Node> = crate::parser::traverse_calls_only(tree.root_node(), language_support).collect();

        for node in call_nodes.iter() {
            if let Some(func_name) = language_support.get_function_name(node, source) {
                let relevant_rules: Vec<(usize, &crate::rules::UnifiedRule)> = rules.iter().enumerate()
                    .filter(|(_, rule)| Self::rule_might_match_function(*rule, &func_name))
                    .map(|(idx, rule)| (idx, *rule))
                    .collect();

                for (_, rule) in relevant_rules {
                    if let Some(finding) = Self::check_rule_against_node(
                        rule,
                        node,
                        source,
                        filepath,
                        &func_name,
                        language_support,
                    ) {
                        let line_key = (finding.line, finding.function.clone(), finding.finding_type.clone());
                        if !processed_lines.contains(&line_key) {
                            processed_lines.insert(line_key);
                            findings.push(finding);
                        }
                    }
                }
            }
        }

        if language_support.name() == "javascript" || language_support.name() == "typescript" {
            Self::scan_assignments(tree.root_node(), source, filepath, rules, language_support, &mut findings, &mut processed_lines);
        }

        findings
    }

    fn scan_assignments(
        node: tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        rules: &[&crate::rules::UnifiedRule],
        language_support: &dyn crate::language::LanguageSupport,
        findings: &mut Vec<crate::models::Finding>,
        processed_lines: &mut std::collections::HashSet<(usize, String, String)>,
    ) {
        let assignment_rules: Vec<&crate::rules::UnifiedRule> = rules.iter()
            .filter(|rule| Self::rule_has_assignment_patterns(rule))
            .copied()
            .collect();

        if !assignment_rules.is_empty() {
            Self::scan_node_for_assignments(node, source, filepath, &assignment_rules, language_support, findings, processed_lines);
        }
    }

    fn scan_node_for_assignments(
        node: tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        assignment_rules: &[&crate::rules::UnifiedRule],
        language_support: &dyn crate::language::LanguageSupport,
        findings: &mut Vec<crate::models::Finding>,
        processed_lines: &mut std::collections::HashSet<(usize, String, String)>,
    ) {
        if matches!(node.kind(), "assignment_expression" | "expression_statement") {
            let node_text = crate::parser::get_node_text(&node, source);

            if CommonUtils::is_valid_assignment_text(&node_text) {
                let assignment_target = CommonUtils::extract_variable_from_assignment(&node_text, true).unwrap_or_default();

                for rule in assignment_rules {
                    if Self::rule_might_match_assignment(rule, &node_text) {
                        if let Some(finding) = Self::check_rule_against_node(
                            rule, &node, source, filepath, &assignment_target, language_support,
                        ) {
                            let line_key = (finding.line, finding.function.clone(), finding.finding_type.clone());
                            if !processed_lines.contains(&line_key) {
                                processed_lines.insert(line_key);
                                findings.push(finding);
                            }
                        }
                    }
                }
            }
        }

        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                Self::scan_node_for_assignments(cursor.node(), source, filepath, assignment_rules, language_support, findings, processed_lines);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn rule_has_assignment_patterns(rule: &crate::rules::UnifiedRule) -> bool {
        const ASSIGNMENT_INDICATORS: &[&str] = &[
            "innerHTML", "outerHTML", "location", "localStorage", 
            "sessionStorage", "__proto__", "=", "prototype"
        ];

        let check_pattern = |pattern: &str| {
            ASSIGNMENT_INDICATORS.iter().any(|indicator| pattern.contains(indicator))
        };

        if let Some(patterns) = &rule.patterns {
            patterns.iter().any(|p| check_pattern(p))
        } else if let Some(pattern) = &rule.pattern {
            check_pattern(pattern)
        } else {
            false
        }
    }

    fn rule_might_match_assignment(rule: &crate::rules::UnifiedRule, node_text: &str) -> bool {
        const ASSIGNMENT_INDICATORS: &[&str] = &[
            "innerHTML", "outerHTML", "location", "localStorage", 
            "sessionStorage", "__proto__", "="
        ];

        let check_and_match = |pattern: &str| {
            ASSIGNMENT_INDICATORS.iter().any(|indicator| pattern.contains(indicator)) &&
            CommonUtils::matches_rule_pattern(pattern, node_text)
        };

        if let Some(patterns) = &rule.patterns {
            patterns.iter().any(|p| check_and_match(p))
        } else if let Some(pattern) = &rule.pattern {
            check_and_match(pattern)
        } else {
            false
        }
    }



    fn detect_source_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        _language_support: &dyn crate::language::LanguageSupport,
    ) -> Option<crate::models::SourceInfo> {
        let node_text = crate::parser::get_node_text(node, source);

        const SOURCE_PATTERNS: &[(&str, &str)] = &[
            ("request", "HTTP Request"), ("input", "User Input"), ("sys.argv", "Command Line"),
            ("environ", "Environment Variable"), ("cookie", "HTTP Cookie"), ("header", "HTTP Header"),
            ("form", "Form Data"), ("query", "Query Parameter"), ("file", "File Input"),
            ("socket", "Network Socket"), ("subprocess", "External Process"), ("json.loads", "JSON Parsing"),
            ("pickle.loads", "Pickle Deserialization"), ("eval", "Dynamic Evaluation"), ("exec", "Dynamic Execution")
        ];

        SOURCE_PATTERNS.iter()
            .find(|(pattern, _)| node_text.contains(pattern))
            .map(|(_, source_type)| crate::models::SourceInfo {
                source_type: source_type.to_string(),
                location: format!("Line {}", node.start_position().row + 1),
                context: crate::scanner::utils::AstUtils::get_function_context(node, source),
            })
    }

    fn detect_sink_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        func_name: &str,
        finding_type: &str,
    ) -> Option<crate::models::SinkInfo> {
        let node_text = crate::parser::get_node_text(node, source);
        let finding_lower = finding_type.to_lowercase();

        let sink_category = match finding_lower.as_str() {
            s if s.contains("sql") => "Database Query",
            s if s.contains("command") => "Command Execution",
            s if s.contains("path") => "File System",
            s if s.contains("xss") => "Web Output",
            _ => "General Sink",
        };

        Some(crate::models::SinkInfo {
            sink_type: sink_category.to_string(),
            function_name: func_name.to_string(),
            location: format!("Line {}", node.start_position().row + 1),
            variable: CommonUtils::extract_variable_from_pattern(&node_text),
        })
    }



    fn should_apply_rule_with_sanitization(rule: &crate::rules::UnifiedRule, node_text: &str) -> bool {
        let finding_type = rule.get_finding_type().to_lowercase();

        if finding_type.contains("xss") || finding_type.contains("dom") {
            !crate::scanner::utils::AstUtils::check_for_sanitization(node_text, "javascript")
        } else if finding_type.contains("prototype") {
            node_text.contains("__proto__") || 
            node_text.contains("['__proto__']") || 
            node_text.contains("[\"__proto__\"]")
        } else {
            true
        }
    }

    /// Check if a rule might match the function name (optimized pattern-based pre-filter)
    fn rule_might_match_function(rule: &crate::rules::UnifiedRule, func_name: &str) -> bool {
        let patterns_to_check = if let Some(patterns) = &rule.patterns {
            patterns.as_slice()
        } else if let Some(pattern) = &rule.pattern {
            std::slice::from_ref(pattern)
        } else {
            return false;
        };

        for pattern in patterns_to_check {
            if Self::pattern_might_match_function(pattern, func_name) {
                return true;
            }
        }

        false
    }

    fn pattern_might_match_function(pattern: &str, func_name: &str) -> bool {
        if pattern == func_name || pattern.contains(func_name) || func_name.contains(pattern) {
            return true;
        }

        if pattern.contains('*') {
            return CommonUtils::matches_unified_pattern(pattern, func_name);
        }

        // Check specific pattern matches
        const EXACT_MATCHES: &[&str] = &[
            "eval", "Function", "setTimeout", "setInterval", "fetch", 
            "Math.random", "RegExp", "import", "require"
        ];

        const CONTAINS_MATCHES: &[&str] = &[
            "document.write", "console.", "localStorage", "sessionStorage", "postMessage", "axios"
        ];

        if EXACT_MATCHES.contains(&pattern) {
            func_name == pattern
        } else if CONTAINS_MATCHES.iter().any(|p| pattern.contains(p)) {
            CONTAINS_MATCHES.iter().any(|p| pattern.contains(p) && func_name.contains(p))
        } else {
            false
        }
    }





    // Public utility methods for rule access
    pub fn has_matching_rules(rules: &crate::rules::Rules, func_name: &str) -> bool {
        rules.get_search_rules().iter().any(|rule| crate::rules::rule_matches_pattern_unified(rule, func_name))
    }

    pub fn get_all_search_rules(rules: &crate::rules::Rules) -> Vec<&crate::rules::UnifiedRule> {
        rules.get_search_rules()
    }

    pub fn get_all_taint_rules(rules: &crate::rules::Rules) -> Vec<&crate::rules::UnifiedRule> {
        rules.get_taint_rules()
    }

    pub fn count_total_rules(rules: &crate::rules::Rules) -> usize {
        rules.count_rules()
    }

    // Public methods for finding creation and validation
    pub fn has_injection_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        language_support: &dyn crate::language::LanguageSupport,
    ) -> bool {
        if let Some(args_node) = language_support.get_arguments_node(node) {
            for i in 0..args_node.named_child_count() {
                if let Some(arg) = args_node.named_child(i) {
                    let arg_text = crate::parser::get_node_text(&arg, source);
                    if !crate::rules::is_literal_node(&arg) && 
                       crate::rules::check_for_injection_pattern(&arg_text, language_support) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn add_finding_metadata(finding: &mut crate::models::Finding, rule: &crate::rules::UnifiedRule, _node: &tree_sitter::Node) {
        finding.severity = rule.get_severity().to_string();
        finding.confidence = rule.get_confidence().to_string();
        finding.description = rule.description.clone();
        finding.tags = rule.tags.clone();
    }

    pub fn create_finding(
        file: &str,
        node: &tree_sitter::Node,
        function: &str,
        finding_type: &str,
        source: &[u8],
        severity: &str,
    ) -> crate::models::Finding {
        crate::models::Finding {
            file: file.to_string(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            end_line: node.end_position().row + 1,
            end_column: node.end_position().column + 1,
            function: function.to_string(),
            finding_type: finding_type.to_string(),
            severity: severity.to_string(),
            confidence: "Medium".to_string(),
            snippet: crate::parser::get_node_text(node, source),
            description: None,
            source_info: None,
            sink_info: None,
            traces: None,
            tags: None,
        }
    }

    /// Scan file with taint analysis rules (fixed implementation with proper flow tracking)
    pub fn scan_file_with_taint_rules(
        filepath: &str,
        source: &[u8],
        tree: &tree_sitter::Tree,
        taint_rules: &[&crate::rules::UnifiedRule],
        language_support: &dyn crate::language::LanguageSupport,
    ) -> Vec<crate::models::Finding> {
        let mut findings = Vec::new();

        // Create rule deduplicator to prevent cartesian product problems
        let rule_deduplicator = TaintRuleDeduplicator::new(taint_rules);

        // Create variable flow tracker for legitimate flows only
        let mut flow_tracker = VariableFlowTracker::new();

        // Use broader traversal to include assignment statements
        let mut all_nodes = Vec::new();
        Self::collect_all_relevant_nodes(tree.root_node(), &mut all_nodes, None);



        // Phase 1: Track variable assignments from taint sources
        for node in all_nodes.iter() {
            let node_text = crate::parser::get_node_text(node, source);
            let line = node.start_position().row + 1;
            let func_name = crate::scanner::utils::AstUtils::get_function_context(node, source);

            // Look for assignment patterns: var = source_call()
            if CommonUtils::is_valid_assignment_text(&node_text) {
                if let Some(var_name) = CommonUtils::extract_variable_from_assignment(&node_text, false) {
                    // Extract the right side of assignment for source matching
                    if let Some(eq_pos) = node_text.find('=') {
                        let assignment_value = &node_text[eq_pos + 1..].trim();
                        // Check if the assignment value matches any taint source
                        if let Some(source_pattern) = rule_deduplicator.matches_source_pattern(assignment_value) {
                            flow_tracker.record_tainted_variable(
                                var_name,
                                TaintVariableInfo {
                                    source_line: line,
                                    source_pattern,
                                    source_function: func_name,
                                    assignment_code: node_text.clone(),
                                }
                            );
                        }
                    }
                }
            }

            // Check for taint propagation through operations
            if let Some((source_var, dependent_vars)) = Self::detect_taint_propagation(&node_text) {
                flow_tracker.record_taint_propagation(&source_var, &dependent_vars);
            }
        }

        // Phase 2: Find sinks that use tainted variables
        for node in all_nodes.iter() {
            let node_text = crate::parser::get_node_text(node, source);
            let line = node.start_position().row + 1;
            let func_name = crate::scanner::utils::AstUtils::get_function_context(node, source);

            // Check if this node matches any sink pattern
            if let Some(sink_pattern) = rule_deduplicator.matches_sink_pattern(&node_text) {
                // Extract ALL variables used in this sink (enhanced extraction)
                let used_variables = CommonUtils::extract_all_variables(&node_text);

                // Check if ANY of these variables are tainted
                for used_variable in used_variables.clone() {
                    if let Some(taint_info) = flow_tracker.is_variable_tainted(&used_variable, &func_name).cloned() {
                        // Check if we have a legitimate rule for this source-sink combination
                        if let Some(rule) = rule_deduplicator.get_rule_for_combination(&taint_info.source_pattern, &sink_pattern) {
                            // Ensure we haven't already processed this exact flow
                            if !flow_tracker.is_flow_processed(line, &taint_info.source_pattern, &sink_pattern) {
                                flow_tracker.mark_flow_processed(line, &taint_info.source_pattern, &sink_pattern);

                                // Create legitimate taint finding
                                let taint_source = crate::models::TaintSource {
                                    file: filepath.to_string(),
                                    line: taint_info.source_line,
                                    function: taint_info.source_function.clone(),
                                    variable: used_variable.clone(),
                                    operation: taint_info.source_pattern.clone(),
                                    code: taint_info.assignment_code.clone(),
                                    branch_id: None,
                                };

                                let taint_sink = crate::models::TaintSink {
                                    file: filepath.to_string(),
                                    line,
                                    function: func_name.clone(),
                                    variable: used_variable.clone(),
                                    operation: sink_pattern.clone(),
                                    code: node_text.clone(),
                                    branch_id: None,
                                };

                                findings.push(Self::create_taint_finding(&taint_source, &taint_sink, rule, tree, source));
                            }
                        }
                    }
                }
            }
        }
        findings
    }



    /// Detect taint propagation in expressions
    fn detect_taint_propagation(node_text: &str) -> Option<(String, Vec<String>)> {
        // Check for F-string propagation
        if node_text.contains('{') && node_text.contains('}') {
            if let Some(source_var) = Self::extract_direct_variable(node_text) {
                let dependent_vars = CommonUtils::extract_f_string_variables(node_text);
                if !dependent_vars.is_empty() {
                    return Some((source_var, dependent_vars));
                }
            }
        }

        // Check for format propagation
        if node_text.contains(".format(") {
            if let Some(source_var) = Self::extract_direct_variable(node_text) {
                let dependent_vars = CommonUtils::extract_format_variables(node_text);
                if !dependent_vars.is_empty() {
                    return Some((source_var, dependent_vars));
                }
            }
        }

        None
    }

    /// Extract direct variable from simple expressions
    fn extract_direct_variable(expr: &str) -> Option<String> {
        let trimmed = expr.trim();
        if CommonUtils::is_valid_variable_name(trimmed) {
            return Some(trimmed.to_string());
        }
        None
    }







    /// Collect all relevant nodes for taint analysis (assignments and calls)
    /// Unified version that supports optional source filtering
    fn collect_all_relevant_nodes<'a>(node: tree_sitter::Node<'a>, nodes: &mut Vec<tree_sitter::Node<'a>>, source: Option<&[u8]>) {
        // Include assignment and call nodes
        match node.kind() {
            "assignment" | "call" | "expression_statement" | "assignment_expression" => {
                // Apply source filtering if provided
                if let Some(source_bytes) = source {
                    let node_text = crate::parser::get_node_text(&node, source_bytes);
                    if !node_text.trim().is_empty() &&
                       !node_text.starts_with('"') &&
                       !node_text.starts_with("'") &&
                       !node_text.contains("__all__") {
                        nodes.push(node);
                    }
                } else {
                    nodes.push(node);
                }
            }
            "import_statement" | "import_from_statement" | "function_definition" |
            "return_statement" | "binary_expression" | "identifier" => {
                if source.is_some() {
                    // Only collect these additional types when doing source filtering
                    let node_text = crate::parser::get_node_text(&node, source.unwrap());
                    if !node_text.trim().is_empty() &&
                       !node_text.starts_with('"') &&
                       !node_text.starts_with("'") &&
                       !node_text.contains("__all__") {
                        nodes.push(node);
                    }
                }
            }
            // Skip string literals, comments, and metadata
            "string" | "string_literal" | "comment" | "module" => {
                // Don't collect these
            }
            _ => {
                // For other node types, check if they contain actual code when source filtering is enabled
                if let Some(source_bytes) = source {
                    let node_text = crate::parser::get_node_text(&node, source_bytes);
                    if !node_text.trim().is_empty() &&
                       !node_text.starts_with('"') &&
                       !node_text.starts_with("'") &&
                       !node_text.contains("__all__") {
                        nodes.push(node);
                    }
                }
            }
        }

        // Recursively traverse children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                Self::collect_all_relevant_nodes(cursor.node(), nodes, source);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Create taint finding from source-sink pair (reusing existing infrastructure)
    fn create_taint_finding(
        source: &crate::models::TaintSource,
        sink: &crate::models::TaintSink,
        rule: &crate::rules::UnifiedRule,
        _tree: &tree_sitter::Tree,
        _source_bytes: &[u8],
    ) -> crate::models::Finding {
        crate::models::Finding {
            file: sink.file.clone(),
            line: sink.line,
            column: 0,
            end_line: sink.line,
            end_column: 0,
            function: sink.function.clone(),
            finding_type: rule.finding_type.clone().unwrap_or_else(|| "Taint Flow".to_string()),
            snippet: sink.code.clone(),
            severity: rule.severity.clone().unwrap_or_else(|| "High".to_string()),
            confidence: rule.confidence.clone().unwrap_or_else(|| "Medium".to_string()),
            description: rule.description.clone().or_else(|| Some(format!(
                "Taint flow detected from {} (line {}) to {} (line {})",
                source.operation, source.line, sink.operation, sink.line
            ))),
            source_info: Some(crate::models::SourceInfo {
                source_type: source.operation.clone(),
                location: format!("{}:{}", source.file, source.line),
                context: source.code.clone(),
            }),
            sink_info: Some(crate::models::SinkInfo {
                sink_type: sink.operation.clone(),
                function_name: sink.function.clone(),
                location: format!("{}:{}", sink.file, sink.line),
                variable: Some(sink.variable.clone()),
            }),
            traces: None,
            tags: Some(vec![
                "taint_analysis".to_string(),
                "data_flow".to_string(),
                rule.category.clone().unwrap_or_else(|| "injection".to_string()),
            ]),
        }
    }


}

// ============================================================================
// INTERNAL UTILITIES - Parser management and helper functions  
// ============================================================================

thread_local! {
    static TLS_PARSER: RefCell<Option<(String, LanguageParser)>> = RefCell::new(None);
}

fn with_local_parser<F, R>(language: &str, f: F) -> Result<R>
where
    F: FnOnce(&mut LanguageParser) -> Result<R>,
{
    TLS_PARSER.try_with(|cell| {
        let mut opt = cell.borrow_mut();
        match *opt {
            Some((ref lang, ref mut parser)) if lang == language => f(parser),
            _ => {
                let mut parser = LanguageParser::new(language)?;
                let result = f(&mut parser)?;
                *opt = Some((language.to_string(), parser));
                Ok(result)
            }
        }
    })?
}

// ============================================================================
// PUBLIC API - Main vulnerability scanner interface
// ============================================================================

/// Main vulnerability scanner providing high-level scanning functionality
pub struct VulnerabilityScanner {
    language: String,
    rules: Rules,
    skip_minified: bool,
}

impl VulnerabilityScanner {
    pub fn new(language_name: &str, rules: Rules) -> Result<Self> {
        Ok(Self {
            language: language_name.to_string(),
            rules,
            skip_minified: true,
        })
    }

    pub fn with_skip_minified(language_name: &str, rules: Rules, skip_minified: bool) -> Result<Self> {
        Ok(Self {
            language: language_name.to_string(),
            rules,
            skip_minified,
        })
    }

    fn discover_files(&self, root_dir: &str) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        // Get extension once using a fresh parser (cheap, happens only once)
        let parser = LanguageParser::new(&self.language)?;
        let target_extension = parser.file_extension();

        for entry in WalkDir::new(root_dir)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if e.file_type().is_dir() {
                    if let Some(name) = e.file_name().to_str() {
                        return !SKIP_DIRS.contains(&name);
                    }
                }
                true
            })
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if format!(".{}", ext) == target_extension {
                        files.push(path.to_path_buf());
                    }
                }
            }
        }
        Ok(files)
    }

    pub fn find_vulnerabilities_parallel(&self, root_dir: &str, language_name: &str, show_progress: bool) -> Result<Vec<Finding>> {
        let files = self.discover_files(root_dir)?;
        if files.is_empty() {
            println!("No {} files found in {}", language_name, root_dir);
            return Ok(Vec::new());
        }

        // Apply pre-filtering to discovered files
        let prefilter = crate::scanner::prefilter::PreFilter::with_options(
            &self.rules,
            language_name,
            self.skip_minified,
            Vec::new() // No custom patterns in simplified version
        );
        let (filtered_files, filter_stats) = prefilter.filter_files(files);

        if show_progress {
            println!("{}", filter_stats);
        }

        if filtered_files.is_empty() {
            println!("No {} files remaining after filtering", language_name);
            return Ok(Vec::new());
        }

        let mut progress_manager = if show_progress {
            Some(ProgressManager::new(filtered_files.len()))
        } else {
            None
        };
        let total_findings = Arc::new(AtomicUsize::new(0));
        let all_rules = ScanningLogic::get_all_search_rules(&self.rules);
        let chunk_size = crate::config::ScanDefaults::CHUNK_SIZE;

        use rayon::slice::ParallelSlice;

        let processed = Arc::new(AtomicUsize::new(0));

        // Start progress tracking
        if let Some(ref mut progress) = progress_manager {
            progress.start_tracking(Arc::clone(&processed), Arc::clone(&total_findings));
        }

        let findings: Vec<Finding> = filtered_files
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                let mut local_vec = Vec::new();
                for path in chunk {
                    let filepath_str = path.to_string_lossy().to_string();
                    match File::open(&path) {
                        Ok(file) => {
                            match unsafe { Mmap::map(&file) } {
                                Ok(mmap) => {
                                    let source: &[u8] = &mmap;
                                    match with_local_parser(&self.language, |parser| {
                                        let tree = parser.parse(source)?;
                                        Ok(ScanningLogic::scan_file_with_rules(
                                            &filepath_str,
                                            source,
                                            &tree,
                                            &all_rules,
                                            parser.language_support(),
                                        ))
                                    }) {
                                        Ok(file_findings) => {
                                            if !file_findings.is_empty() {
                                                total_findings.fetch_add(file_findings.len(), Ordering::Relaxed);
                                            }
                                            local_vec.extend(file_findings);
                                        }
                                        Err(e) => eprintln!("Failed to parse {}: {}", filepath_str, e),
                                    }
                                }
                                Err(e) => eprintln!("Failed to mmap file {}: {}", filepath_str, e),
                            }
                        }
                        Err(err) => eprintln!("Failed to open file {}: {}", filepath_str, err),
                    }
                }
                processed.fetch_add(chunk.len(), Ordering::Relaxed);
                local_vec
            })
            .collect();

        // Stop progress tracking
        if let Some(mut progress) = progress_manager {
            progress.stop();
        }
        if show_progress {
            println!("Found {} vulnerabilities", total_findings.load(Ordering::Relaxed));
        }
        Ok(findings)
    }

    pub fn find_vulnerabilities_single_threaded(&self, root_dir: &str, language_name: &str) -> Result<Vec<Finding>> {
        // Reuse the parallel scanner with a single-thread rayon pool.
        rayon::ThreadPoolBuilder::new().num_threads(1).build_global().ok();
        self.find_vulnerabilities_parallel(root_dir, language_name, true)
    }

    pub fn find_vulnerabilities_unified(&self, root_dir: &str, language_name: &str, show_progress: bool) -> Result<Vec<Finding>> {
        let files_by_language = if self.language.is_empty() {
            crate::scanner::utils::discover_files_by_language(root_dir, true)?
        } else {
            let files = self.discover_files(root_dir)?;
            let mut result = std::collections::HashMap::new();
            if !files.is_empty() {
                result.insert(self.language.clone(), files);
            }
            result
        };

        if files_by_language.is_empty() {
            if show_progress {
                println!("No supported files found in {}", root_dir);
            }
            return Ok(Vec::new());
        }

        let all_files: Vec<std::path::PathBuf> = files_by_language.values().flatten().cloned().collect();

        if all_files.is_empty() {
            if show_progress {
                println!("No files found after discovery");
            }
            return Ok(Vec::new());
        }

        let prefilter = crate::scanner::prefilter::PreFilter::with_options(
            &self.rules, language_name, self.skip_minified, Vec::new()
        );
        let (filtered_files, filter_stats) = prefilter.filter_files(all_files);

        if show_progress {
            println!("{}", filter_stats);
        }

        if filtered_files.is_empty() {
            if show_progress {
                println!("No files remaining after filtering");
            }
            return Ok(Vec::new());
        }

        let search_rules = ScanningLogic::get_all_search_rules(&self.rules);
        let taint_rules = ScanningLogic::get_all_taint_rules(&self.rules);

        let has_search_rules = !search_rules.is_empty();
        let has_taint_rules = !taint_rules.is_empty();

        if !has_search_rules && !has_taint_rules {
            if show_progress {
                println!("No applicable rules found");
            }
            return Ok(Vec::new());
        }

        let mut progress_manager = if show_progress {
            Some(ProgressManager::new(filtered_files.len()))
        } else {
            None
        };
        let total_findings = Arc::new(AtomicUsize::new(0));
        let chunk_size = crate::config::ScanDefaults::CHUNK_SIZE;

        use rayon::slice::ParallelSlice;
        let processed = Arc::new(AtomicUsize::new(0));

        if let Some(ref mut progress) = progress_manager {
            progress.start_tracking(Arc::clone(&processed), Arc::clone(&total_findings));
        }

        let single_file_findings: Vec<Finding> = filtered_files
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                let mut local_vec = Vec::new();
                for path in chunk {
                    let filepath_str = path.to_string_lossy().to_string();

                    // Auto-detect language for each file
                    if let Some(detected_language) = crate::scanner::utils::detect_language_from_path(path) {
                        match File::open(&path) {
                            Ok(file) => {
                                match unsafe { Mmap::map(&file) } {
                                    Ok(mmap) => {
                                        let source: &[u8] = &mmap;
                                        match with_local_parser(detected_language, |parser| {
                                            let tree = parser.parse(source)?;

                                            let mut file_findings = Vec::new();

                                            // Search mode findings (existing functionality)
                                            if has_search_rules {
                                                file_findings.extend(ScanningLogic::scan_file_with_rules(
                                                    &filepath_str, source, &tree, &search_rules, parser.language_support()
                                                ));
                                            }

                                            // Single-file taint mode findings (existing functionality)
                                            if has_taint_rules {
                                                file_findings.extend(ScanningLogic::scan_file_with_taint_rules(
                                                    &filepath_str, source, &tree, &taint_rules, parser.language_support()
                                                ));
                                            }

                                            Ok(file_findings)
                                        }) {
                                            Ok(file_findings) => {
                                                if !file_findings.is_empty() {
                                                    total_findings.fetch_add(file_findings.len(), Ordering::Relaxed);
                                                }
                                                local_vec.extend(file_findings);
                                            }
                                            Err(e) => eprintln!("Failed to parse {}: {}", filepath_str, e),
                                        }
                                    }
                                    Err(e) => eprintln!("Failed to mmap file {}: {}", filepath_str, e),
                                }
                            }
                            Err(err) => eprintln!("Failed to open file {}: {}", filepath_str, err),
                        }
                    }
                }
                processed.fetch_add(chunk.len(), Ordering::Relaxed);
                local_vec
            })
            .collect();

        // Phase 2: Multi-file taint analysis (NEW functionality)
        let mut cross_file_findings = Vec::new();
        if has_taint_rules && filtered_files.len() > 1 {
            if show_progress {
                println!("🔍 Performing cross-file taint analysis...");
            }

            let mut multi_file_analyzer = MultiFileTaintAnalyzer::new();
            match multi_file_analyzer.analyze_cross_file_flows(&files_by_language, &taint_rules) {
                Ok(findings) => {
                    cross_file_findings = findings;
                    if show_progress && !cross_file_findings.is_empty() {
                        println!("✅ Found {} cross-file taint flows", cross_file_findings.len());
                    }
                }
                Err(e) => {
                    if show_progress {
                        eprintln!("⚠️  Cross-file analysis failed: {}", e);
                    }
                }
            }
        }

        // Stop progress tracking (reuse existing infrastructure)
        if let Some(mut progress) = progress_manager {
            progress.stop();
        }

        // Combine all findings
        let mut all_findings = single_file_findings;
        all_findings.extend(cross_file_findings);

        if show_progress {
            let search_count = all_findings.iter().filter(|f| {
                f.tags.as_ref().map_or(true, |tags| !tags.contains(&"taint_analysis".to_string()))
            }).count();
            let single_file_taint_count = all_findings.iter().filter(|f| {
                f.tags.as_ref().map_or(false, |tags|
                    tags.contains(&"taint_analysis".to_string()) && !tags.contains(&"cross_file".to_string())
                )
            }).count();
            let cross_file_taint_count = all_findings.iter().filter(|f| {
                f.tags.as_ref().map_or(false, |tags| tags.contains(&"cross_file".to_string()))
            }).count();

            if has_search_rules && has_taint_rules {
                println!("Found {} search findings, {} single-file taint flows, {} cross-file taint flows",
                        search_count, single_file_taint_count, cross_file_taint_count);
            } else if has_search_rules {
                println!("Found {} search findings", search_count);
            } else {
                println!("Found {} single-file taint flows, {} cross-file taint flows",
                        single_file_taint_count, cross_file_taint_count);
            }
        }

        Ok(all_findings)
    }
}

// ============================================================================
// OUTPUT & REPORTING - Progress tracking and result formatting
// ============================================================================

pub fn print_summary(findings: &[Finding], duration: std::time::Duration) {
    println!("\n\x1b[1;36m=== Vulnerability Summary ===\x1b[0m");

    // Group findings by severity
    let mut severity_counts: HashMap<String, usize> = HashMap::new();
    let mut finding_types: HashMap<String, usize> = HashMap::new();
    let mut file_counts: HashMap<String, usize> = HashMap::new();

    for finding in findings {
        *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
        *finding_types.entry(finding.finding_type.clone()).or_insert(0) += 1;
        *file_counts.entry(finding.file.clone()).or_insert(0) += 1;
    }

    // Print severity breakdown
    println!("\n\x1b[1;33mSeverity Breakdown:\x1b[0m");
    let severity_order = ["critical", "high", "medium", "low"];
    for severity in severity_order {
        if let Some(count) = severity_counts.get(severity) {
            let color = match severity {
                "critical" => "\x1b[31;1m", // Bright red
                "high" => "\x1b[31m",      // Red
                "medium" => "\x1b[33m",    // Yellow
                "low" => "\x1b[32m",       // Green
                _ => "\x1b[0m",
            };
            println!("  {}{}\x1b[0m {} findings",
                    color,
                    "●",
                    count);
        }
    }

    // Print finding types
    println!("\n\x1b[1;33mFinding Types:\x1b[0m");
    let mut sorted_types: Vec<_> = finding_types.iter().collect();
    sorted_types.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count descending
    for (finding_type, count) in sorted_types {
        println!("  \x1b[36m●\x1b[0m {}: {} occurrences", finding_type, count);
    }

    // Print most vulnerable files
    println!("\n\x1b[1;33mMost Vulnerable Files:\x1b[0m");
    let mut sorted_files: Vec<_> = file_counts.iter().collect();
    sorted_files.sort_by(|a, b| b.1.cmp(a.1));
    for (file_path, count) in sorted_files.iter().take(5) {
        println!("  \x1b[34m●\x1b[0m {}: {} vulnerabilities", file_path, count);
    }

    // Print total
    println!("\n\x1b[1;36mTotal Findings: \x1b[1;33m{}\x1b[0m", findings.len());
    println!("\x1b[1;36mScan Time: \x1b[1;33m{:.2?}\x1b[0m", duration);
}

/// Progress bar management for vulnerability scanning
pub struct ProgressManager {
    bar: ProgressBar,
    should_stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ProgressManager {
    /// Create a new progress manager
    pub fn new(total: usize) -> Self {
        let bar = ProgressBar::new(total as u64);
        if let Ok(style) = ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files {msg}") {
            bar.set_style(style.progress_chars("#>-"));
        }
        bar.set_draw_target(ProgressDrawTarget::stderr());

        Self {
            bar,
            should_stop: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    /// Start tracking progress with counters
    pub fn start_tracking(&mut self, processed: Arc<AtomicUsize>, findings: Arc<AtomicUsize>) {
        let bar_clone = self.bar.clone();
        let stop_clone = Arc::clone(&self.should_stop);

        self.handle = Some(std::thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                let val = processed.load(Ordering::Relaxed) as u64;
                bar_clone.set_position(val);
                let vulns = findings.load(Ordering::Relaxed);
                bar_clone.set_message(format!("| {} vulns", vulns));
                std::thread::sleep(Duration::from_millis(crate::config::ScanDefaults::PROGRESS_INTERVAL_MS));
            }
        }));
    }

    /// Update progress bar message
    pub fn set_message(&self, message: String) {
        self.bar.set_message(message);
    }

    /// Stop progress tracking
    pub fn stop(&mut self) {
        self.should_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.bar.finish_with_message("Scan complete");
    }
}

/// Print findings in JSON format
pub fn print_findings_json(findings: &[Finding]) {
    match serde_json::to_string_pretty(findings) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error serializing findings to JSON: {}", e),
    }
}

/// Print findings in CSV format
pub fn print_findings_csv(findings: &[Finding]) {
    println!("file,line,function,finding_type,code,severity,confidence,source_type,source_context,sink_type,sink_function,traces");
    for finding in findings {
        let code = finding.snippet.replace('"', "\"\"");
        let source_type = finding.source_info.as_ref().map(|s| s.source_type.as_str()).unwrap_or("");
        let source_context = finding.source_info.as_ref().map(|s| s.context.as_str()).unwrap_or("");
        let sink_type = finding.sink_info.as_ref().map(|s| s.sink_type.as_str()).unwrap_or("");
        let sink_function = finding.sink_info.as_ref().map(|s| s.function_name.as_str()).unwrap_or("");

        let traces = if let Some(traces) = &finding.traces {
            traces.iter()
                .map(|t| format!("{}:{}:{}", t.line, t.variable, t.operation))
                .collect::<Vec<_>>()
                .join(";")
        } else {
            String::new()
        };

        println!("{},{},{},{},\"{}\",{},{},{},{},{},{},\"{}\"",
                finding.file, finding.line, finding.function, finding.finding_type,
                code, finding.severity, finding.confidence, source_type, source_context, sink_type, sink_function, traces);
    }
}

/// Print findings in text format with syntax highlighting
pub fn print_findings_text(findings: &[Finding], _verbose: bool, summary_only: bool, duration: std::time::Duration) {
    if !summary_only {
        // Initialize syntax highlighting
        let ps = SyntaxSet::load_defaults_newlines();
        let ts = ThemeSet::load_defaults();
        let theme = &ts.themes["base16-ocean.dark"];

        // Pre-sort findings by file and severity for better grouping
        let mut sorted_findings: Vec<_> = findings.iter().collect();
        sorted_findings.sort_by(|a, b| {
            a.file.cmp(&b.file)
                .then(a.severity.cmp(&b.severity))
                .then(a.line.cmp(&b.line))
        });

        // Group findings by file
        let mut current_file = None;
        let mut file_contents: String;
        let mut lines = Vec::new();
        let mut syntax = None;

        for finding in sorted_findings {
            // Only read file when it changes
            if current_file != Some(&finding.file) {
                current_file = Some(&finding.file);
                file_contents = match fs::read_to_string(&finding.file) {
                    Ok(contents) => contents,
                    Err(_) => continue,
                };
                lines = file_contents.lines().collect();


                // Set up syntax highlighting for the new file
                let syntax_name = CommonUtils::detect_syntax(&finding.file);
                syntax = ps.find_syntax_by_name(syntax_name);

                println!("\n\x1b[1;34m{}\x1b[0m", finding.file);
            }

            let severity_color = match finding.severity.to_lowercase().as_str() {
                "critical" => "\x1b[31m", // Red
                "high" => "\x1b[31;1m",   // Bright red
                "medium" => "\x1b[33m",   // Yellow
                "low" => "\x1b[32m",      // Green
                _ => "\x1b[0m",           // Default
            };

            let line_num = finding.line;
            let start_line = line_num.saturating_sub(3);
            let end_line = (line_num + 3).min(lines.len());

            println!("");
            println!("    {}{}●\x1b[0m {} on line {}",
                    severity_color,
                    severity_color,
                    finding.finding_type,
                    line_num);

            // Display source and sink information if available
            if let Some(source_info) = &finding.source_info {
                println!("    📍 Source: {} ({})", source_info.source_type, source_info.context);
            }

            if let Some(sink_info) = &finding.sink_info {
                println!("    🎯 Sink: {} ({})", sink_info.sink_type, sink_info.function_name);
                if let Some(var) = &sink_info.variable {
                    println!("       Variable: {}", var);
                }
            }

            // Display traces if available
            if let Some(traces) = &finding.traces {
                if !traces.is_empty() {
                    println!("    🔄 Data Flow Traces:");
                    for (i, trace) in traces.iter().enumerate() {
                        println!("       {}. {}:{} - {} ({}) in {}",
                                i + 1,
                                trace.line,
                                trace.variable,
                                trace.operation,
                                trace.code.chars().take(50).collect::<String>(),
                                trace.function);
                    }
                }
            }

            println!();

            // Print surrounding context with syntax highlighting
            if let Some(syntax) = syntax {
                let mut h = HighlightLines::new(syntax, theme);
                for i in start_line..end_line {
                    let line = lines[i];
                    let ranges: Vec<(Style, &str)> = h.highlight_line(line, &ps).unwrap_or_default();
                    let prefix = if i + 1 == line_num { "\x1b[31m>>\x1b[0m" } else { "  " };
                    print!("    {}{:4} | ", prefix, i + 1);

                    for (style, text) in ranges {
                        let fg = style.foreground;
                        print!("\x1b[38;2;{};{};{}m{}\x1b[0m",
                            fg.r, fg.g, fg.b, text);
                    }
                    println!();
                }
            } else {
                // Fallback to plain text if syntax highlighting fails
                for i in start_line..end_line {
                    let prefix = if i + 1 == line_num { "\x1b[31m>>\x1b[0m" } else { "  " };
                    println!("    {}{:4} | {}", prefix, i + 1, lines[i]);
                }
            }
            println!();
        }
    }
    print_summary(findings, duration);
}

// ============================================================================
// TAINT ANALYSIS ENGINE - Variable flow tracking and cross-file analysis
// ============================================================================

/// Variable flow tracker for legitimate taint analysis
#[derive(Debug)]
struct VariableFlowTracker {
    /// Maps variable names to their taint source information
    tainted_variables: std::collections::HashMap<String, TaintVariableInfo>,
    /// Function scopes to handle variable visibility
    function_scopes: std::collections::HashMap<String, std::collections::HashSet<String>>,
    /// Taint propagation through operations
    taint_propagations: std::collections::HashMap<String, Vec<String>>, // var -> [dependent_vars]
    /// Deduplication set for flows to prevent duplicates
    processed_flows: std::collections::HashSet<(usize, String, String)>, // (line, source_pattern, sink_pattern)
}

#[derive(Debug, Clone)]
struct TaintVariableInfo {
    source_line: usize,
    source_pattern: String,
    source_function: String,
    assignment_code: String,
}

impl VariableFlowTracker {
    fn new() -> Self {
        Self {
            tainted_variables: std::collections::HashMap::new(),
            function_scopes: std::collections::HashMap::new(),
            taint_propagations: std::collections::HashMap::new(),
            processed_flows: std::collections::HashSet::new(),
        }
    }

    /// Record a variable as tainted from a source
    fn record_tainted_variable(&mut self, var_name: String, source_info: TaintVariableInfo) {
        self.tainted_variables.insert(var_name.clone(), source_info.clone());

        // Add to function scope
        self.function_scopes
            .entry(source_info.source_function.clone())
            .or_insert_with(std::collections::HashSet::new)
            .insert(var_name);
    }

    /// Check if a variable is tainted
    fn is_variable_tainted(&self, var_name: &str, function: &str) -> Option<&TaintVariableInfo> {
        // Check direct variable
        if let Some(info) = self.tainted_variables.get(var_name) {
            // Same function or global variable
            if info.source_function == function || Self::is_global_variable(var_name) {
                return Some(info);
            }
        }
        None
    }

    /// Check if we've already processed this flow to prevent duplicates
    fn is_flow_processed(&self, line: usize, source_pattern: &str, sink_pattern: &str) -> bool {
        self.processed_flows.contains(&(line, source_pattern.to_string(), sink_pattern.to_string()))
    }

    /// Mark a flow as processed
    fn mark_flow_processed(&mut self, line: usize, source_pattern: &str, sink_pattern: &str) {
        self.processed_flows.insert((line, source_pattern.to_string(), sink_pattern.to_string()));
    }

    /// Record taint propagation through operations
    fn record_taint_propagation(&mut self, source_var: &str, dependent_vars: &[String]) {
        for dep_var in dependent_vars {
            self.taint_propagations
                .entry(source_var.to_string())
                .or_insert_with(Vec::new)
                .push(dep_var.clone());
        }
    }

    /// Check if any variable in a list is tainted
    fn is_any_variable_tainted(&self, variables: &[String], function: &str) -> Option<&TaintVariableInfo> {
        for var in variables {
            if let Some(info) = self.is_variable_tainted(var, function) {
                return Some(info);
            }
        }
        None
    }

    /// Check if variable is likely global/passed between functions (reusing existing logic)
    fn is_global_variable(var_name: &str) -> bool {
        // Simple heuristics for global variables
        var_name.to_uppercase() == var_name || // ALL_CAPS
        var_name.starts_with("app.") ||        // app.something
        var_name.contains("_DIR") ||           // paths
        var_name.contains("_PATH")             // paths
    }
}

/// Multi-file taint analysis infrastructure for cross-file data flow tracking
#[derive(Debug)]
struct MultiFileTaintAnalyzer {
    /// Maps file paths to their exported functions/variables
    file_exports: std::collections::HashMap<String, FileExports>,
    /// Maps file paths to their imported functions/variables
    file_imports: std::collections::HashMap<String, FileImports>,
    /// Cross-file taint flows that span multiple files
    cross_file_flows: Vec<CrossFileTaintFlow>,
    /// Deduplication set for cross-file flows
    processed_cross_file_flows: std::collections::HashSet<(String, String, String, String)>, // (source_file, source_func, sink_file, sink_func)
}

#[derive(Debug, Clone)]
struct FileExports {
    /// Functions exported from this file
    functions: std::collections::HashSet<String>,
    /// Variables exported from this file
    variables: std::collections::HashSet<String>,
    /// Taint sources in this file
    taint_sources: Vec<TaintSourceInfo>,
}

#[derive(Debug, Clone)]
struct FileImports {
    /// Functions imported into this file
    functions: std::collections::HashMap<String, String>, // local_name -> source_file
    /// Variables imported into this file
    variables: std::collections::HashMap<String, String>, // local_name -> source_file
    /// Taint sinks in this file
    taint_sinks: Vec<TaintSinkInfo>,
}

#[derive(Debug, Clone)]
struct TaintSourceInfo {
    function: String,
    line: usize,
    pattern: String,
    code: String,
}

#[derive(Debug, Clone)]
struct TaintSinkInfo {
    function: String,
    line: usize,
    pattern: String,
    code: String,
    used_variable: String,
}

#[derive(Debug, Clone)]
struct CrossFileTaintFlow {
    source_file: String,
    source_function: String,
    source_line: usize,
    sink_file: String,
    sink_function: String,
    sink_line: usize,
    flow_path: Vec<String>, // List of files in the flow path
    rule: crate::rules::UnifiedRule,
}

impl MultiFileTaintAnalyzer {
    fn new() -> Self {
        Self {
            file_exports: std::collections::HashMap::new(),
            file_imports: std::collections::HashMap::new(),
            cross_file_flows: Vec::new(),
            processed_cross_file_flows: std::collections::HashSet::new(),
        }
    }

    /// Analyze all files for cross-file taint flows
    fn analyze_cross_file_flows(
        &mut self,
        files_by_language: &std::collections::HashMap<String, Vec<std::path::PathBuf>>,
        taint_rules: &[&crate::rules::UnifiedRule],
    ) -> Result<Vec<crate::models::Finding>> {
        let mut findings = Vec::new();

        // Phase 1: Build import/export maps for all files
        self.build_import_export_maps(files_by_language, taint_rules)?;

        // Phase 2: Use recursive tracing for cross-file taint flows
        let rule_deduplicator = TaintRuleDeduplicator::new(taint_rules);
        for (sink_file, imports) in &self.file_imports {
            for sink_info in &imports.taint_sinks {
                let mut visited = std::collections::HashSet::new();
                if let Some((source_file, source_info, flow_path)) = self.trace_taint_to_source(sink_file, &sink_info.used_variable, &mut visited, 10, 0) {
                    let flow_key = (source_file.clone(), source_info.function.clone(), sink_file.clone(), sink_info.function.clone());
                    if !self.processed_cross_file_flows.contains(&flow_key) {
                        self.processed_cross_file_flows.insert(flow_key);

                        // Create the cross-file flow
                        let cross_file_flow = CrossFileTaintFlow {
                            source_file: source_file.clone(),
                            source_function: source_info.function.clone(),
                            source_line: source_info.line,
                            sink_file: sink_file.clone(),
                            sink_function: sink_info.function.clone(),
                            sink_line: sink_info.line,
                            flow_path,
                            rule: rule_deduplicator.get_rule_for_combination(&source_info.pattern, &sink_info.pattern)
                                .unwrap_or(&taint_rules[0]).clone(),
                        };

                        self.cross_file_flows.push(cross_file_flow.clone());
                        findings.push(self.create_cross_file_finding(&cross_file_flow));
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Build import/export maps for all files
    fn build_import_export_maps(
        &mut self,
        files_by_language: &std::collections::HashMap<String, Vec<std::path::PathBuf>>,
        taint_rules: &[&crate::rules::UnifiedRule],
    ) -> Result<()> {
        let rule_deduplicator = TaintRuleDeduplicator::new(taint_rules);

        for (language, files) in files_by_language {
            if language == "python" {
                for file_path in files {
                    let filepath = file_path.to_string_lossy();
                    let source = std::fs::read(file_path)?;

                    crate::scanner::core::with_local_parser(language, |parser| {
                        let tree = parser.parse(&source)?;
                        let language_support = crate::language::get_language_support(language)?;

                        self.analyze_file_imports_exports(
                            &filepath,
                            &source,
                            &tree,
                            &rule_deduplicator,
                            language_support.as_ref(),
                        );

                        Ok(())
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Analyze a single file for imports, exports, and taint sources/sinks - ENHANCED with better debugging
    fn analyze_file_imports_exports(
        &mut self,
        filepath: &str,
        source: &[u8],
        tree: &tree_sitter::Tree,
        rule_deduplicator: &TaintRuleDeduplicator,
        _language_support: &dyn crate::language::LanguageSupport,
    ) {
        let mut exports = FileExports {
            functions: std::collections::HashSet::new(),
            variables: std::collections::HashSet::new(),
            taint_sources: Vec::new(),
        };

        let mut imports = FileImports {
            functions: std::collections::HashMap::new(),
            variables: std::collections::HashMap::new(),
            taint_sinks: Vec::new(),
        };

        // Collect all relevant nodes with error handling
        let mut all_nodes = Vec::new();
        ScanningLogic::collect_all_relevant_nodes(tree.root_node(), &mut all_nodes, Some(source));

        for node in all_nodes {
            // Safely extract node text to avoid panics
            let node_text = crate::parser::get_node_text(&node, source);

            let line = node.start_position().row + 1;
            let func_name = crate::scanner::utils::AstUtils::get_function_context(&node, source);

            // Skip string literals and metadata
            if node_text.trim().starts_with('"') || node_text.trim().starts_with("'") ||
               node_text.contains("__all__") || node_text.contains("__version__") {
                continue;
            }

            // Check for function definitions
            if crate::scanner::utils::AstUtils::is_function_node(&node) {
                if let Some(function_name) = crate::scanner::utils::AstUtils::extract_function_name(&node, source) {
                    exports.functions.insert(function_name);
                }
            }

            // Check for imports
            if let Some(import_list) = Self::extract_import_info(&node_text) {
                for (func_name, module_name) in import_list {
                    // Convert module name to full file path to match export keys
                    let module_file_path = if module_name.ends_with(".py") {
                        module_name
                    } else {
                        // Convert module_a -> test_files/accuracy_tests/cross_file/module_a.py
                        let base_dir = std::path::Path::new(filepath).parent().unwrap_or(std::path::Path::new(""));
                        let module_file = format!("{}.py", module_name);
                        base_dir.join(module_file).to_string_lossy().to_string()
                    };

                    imports.functions.insert(func_name, module_file_path);
                }
            }

            // Check for taint sources (environment variables, command line args, etc.)
            if let Some(source_pattern) = Self::extract_taint_source_pattern(&node, source, rule_deduplicator) {
                exports.taint_sources.push(TaintSourceInfo {
                    function: func_name.clone(),
                    line,
                    pattern: source_pattern,
                    code: node_text.clone(),
                });
            }

            // ENHANCED: Check if this is a function definition that contains taint sources
            if node.kind() == "function_definition" {
                if Self::function_contains_taint_sources(&node, source, rule_deduplicator) {
                    let function_name = crate::scanner::utils::AstUtils::extract_function_name(&node, source).unwrap_or("unknown".to_string());
                    exports.taint_sources.push(TaintSourceInfo {
                        function: function_name,
                        line,
                        pattern: "function_with_taint_sources".to_string(),
                        code: node_text.clone(),
                    });
                }
            }

            // Check for taint sinks (eval, exec, os.system, etc.)
            if let Some(sink_pattern) = Self::extract_taint_sink_pattern(&node, source, rule_deduplicator) {
                // Extract variables from function call arguments
                let used_variables = CommonUtils::extract_all_variables(&node_text);
                if let Some(first_var) = used_variables.first() {
                    imports.taint_sinks.push(TaintSinkInfo {
                        function: func_name.clone(),
                        line,
                        pattern: sink_pattern,
                        code: node_text.clone(),
                        used_variable: first_var.clone(),
                    });
                }
            }
        }

        self.file_exports.insert(filepath.to_string(), exports);
        self.file_imports.insert(filepath.to_string(), imports);
    }

    /// Extract taint source pattern by analyzing the node more intelligently - ENHANCED for better detection
    fn extract_taint_source_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> Option<String> {
        let node_text = crate::parser::get_node_text(node, source);

        // Skip string literals and other non-code nodes
        if node.kind() == "string" || node.kind() == "string_literal" {
            return None;
        }

        // Check all source patterns against this node
        for pattern in &rule_deduplicator.source_patterns {
            // Direct pattern matching for simple cases
            if CommonUtils::matches_taint_pattern_in_context(pattern, &node_text, node.kind(), "") {
                return Some(pattern.clone());
            }

            // Enhanced pattern matching for complex expressions
            if Self::enhanced_taint_source_matching(pattern, &node_text, node, source) {
                return Some(pattern.clone());
            }
        }

        None
    }



    /// Enhanced taint source matching for complex expressions - NEW function
    fn enhanced_taint_source_matching(
        pattern: &str,
        node_text: &str,
        node: &tree_sitter::Node,
        source: &[u8],
    ) -> bool {
        // Handle os.environ patterns
        if pattern.contains("os.environ") || pattern.contains("os\\.environ") {
            if node_text.contains("os.environ") ||
               node_text.contains("os.getenv") ||
               Self::contains_os_environ_call(node, source) {
                return true;
            }
        }

        // Handle sys.argv patterns
        if pattern.contains("sys.argv") || pattern.contains("sys\\.argv") {
            if node_text.contains("sys.argv") ||
               Self::contains_sys_argv_access(node, source) {
                return true;
            }
        }

        // Handle request patterns (web frameworks)
        if pattern.contains("request") {
            if node_text.contains("request.") ||
               node_text.contains("flask.request") ||
               node_text.contains("django.request") {
                return true;
            }
        }

        // Handle input patterns
        if pattern.contains("input(") || pattern.contains("input\\(") {
            if node_text.contains("input(") ||
               node_text.contains("raw_input(") {
                return true;
            }
        }

        false
    }

    /// Check if node contains os.environ access - NEW function
    fn contains_os_environ_call(node: &tree_sitter::Node, source: &[u8]) -> bool {
        // Check if this node or its children contain os.environ access
        if node.kind() == "attribute" {
            let node_text = crate::parser::get_node_text(node, source);
            if node_text.contains("os.environ") {
                return true;
            }
        }

        // Check for method calls like os.environ.get(), os.getenv()
        if node.kind() == "call" {
            if let Some(func_node) = node.child_by_field_name("function") {
                let func_text = crate::parser::get_node_text(&func_node, source);
                if func_text.contains("os.environ") ||
                   func_text.contains("os.getenv") ||
                   func_text == "getenv" {
                    return true;
                }
            }
        }

        // Recursively check children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if Self::contains_os_environ_call(&cursor.node(), source) {
                    return true;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        false
    }

    /// Check if node contains sys.argv access - NEW function
    fn contains_sys_argv_access(node: &tree_sitter::Node, source: &[u8]) -> bool {
        // Check if this node or its children contain sys.argv access
        if node.kind() == "attribute" || node.kind() == "subscript" {
            let node_text = crate::parser::get_node_text(node, source);
            if node_text.contains("sys.argv") {
                return true;
            }
        }

        // Recursively check children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if Self::contains_sys_argv_access(&cursor.node(), source) {
                    return true;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        false
    }

    /// Extract taint sink pattern by analyzing the node more intelligently - FIXED for context awareness
    fn extract_taint_sink_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> Option<String> {
        let node_text = crate::parser::get_node_text(node, source);

        // Skip string literals and other non-code nodes
        if node.kind() == "string" || node.kind() == "string_literal" {
            return None;
        }

        // For call nodes, extract the function name
        if node.kind() == "call" {
            if let Some(func_name) = crate::scanner::utils::AstUtils::extract_function_name(node, source) {
                // Check if this function name matches any taint sink patterns
                for pattern in &rule_deduplicator.sink_patterns {
                    if Self::function_matches_pattern(&func_name, pattern) {
                        return Some(pattern.clone());
                    }
                }
            }
        }

        // For expression nodes, check the full expression
        if node.kind() == "expression_statement" || node.kind() == "binary_expression" {
            for pattern in &rule_deduplicator.sink_patterns {
                if CommonUtils::matches_taint_pattern_in_context(pattern, &node_text, node.kind(), "expression") {
                    return Some(pattern.clone());
                }
            }
        }

        None
    }





    /// Check if a function name matches a taint pattern
    fn function_matches_pattern(func_name: &str, pattern: &str) -> bool {
        // Clean up the pattern to extract just the function name
        let clean_pattern = pattern
            .replace("\\(", "")
            .replace("\\)", "")
            .replace("\\.", ".")
            .replace("\\\\", "\\");

        // Check if the function name matches the pattern
        if clean_pattern.contains(func_name) {
            return true;
        }

        // Handle patterns like "os\\.system" -> "os.system"
        if clean_pattern.contains(".") && func_name.contains(".") {
            return clean_pattern == func_name;
        }

        // Handle patterns like "eval\\(" -> "eval"
        if clean_pattern.ends_with(func_name) {
            return true;
        }

        false
    }



    /// Create a finding from a cross-file taint flow
    fn create_cross_file_finding(&self, flow: &CrossFileTaintFlow) -> crate::models::Finding {
        let taint_source = crate::models::TaintSource {
            file: flow.source_file.clone(),
            line: flow.source_line,
            function: flow.source_function.clone(),
            variable: flow.source_function.clone(), // Function name as variable
            operation: "cross_file_import".to_string(),
            code: format!("Function exported from {}", flow.source_file),
            branch_id: None,
        };

        let taint_sink = crate::models::TaintSink {
            file: flow.sink_file.clone(),
            line: flow.sink_line,
            function: flow.sink_function.clone(),
            variable: flow.source_function.clone(), // Imported function name
            operation: "cross_file_sink".to_string(),
            code: format!("Imported function used in {}", flow.sink_file),
            branch_id: None,
        };

        crate::models::Finding {
            file: flow.sink_file.clone(),
            line: flow.sink_line,
            column: 0,
            end_line: flow.sink_line,
            end_column: 0,
            function: flow.sink_function.clone(),
            finding_type: flow.rule.finding_type.clone().unwrap_or_else(|| "Cross-File Taint Flow".to_string()),
            snippet: format!("Cross-file flow: {} -> {}", flow.source_file, flow.sink_file),
            severity: flow.rule.severity.clone().unwrap_or_else(|| "High".to_string()),
            confidence: flow.rule.confidence.clone().unwrap_or_else(|| "Medium".to_string()),
            description: flow.rule.description.clone().or_else(|| Some(format!(
                "Cross-file taint flow detected from {} (line {}) to {} (line {})",
                flow.source_function, flow.source_line, flow.sink_function, flow.sink_line
            ))),
            source_info: Some(crate::models::SourceInfo {
                source_type: "cross_file_import".to_string(),
                location: format!("{}:{}", flow.source_file, flow.source_line),
                context: format!("Function exported from {}", flow.source_file),
            }),
            sink_info: Some(crate::models::SinkInfo {
                sink_type: "cross_file_sink".to_string(),
                function_name: flow.sink_function.clone(),
                location: format!("{}:{}", flow.sink_file, flow.sink_line),
                variable: Some(flow.source_function.clone()),
            }),
            traces: None,
            tags: Some(vec![
                "taint_analysis".to_string(),
                "cross_file".to_string(),
                "data_flow".to_string(),
                flow.rule.category.clone().unwrap_or_else(|| "injection".to_string()),
            ]),
        }
    }

    /// Extract import information from node text - FIXED for multi-line imports and parentheses
    fn extract_import_info(text: &str) -> Option<Vec<(String, String)>> {
        let mut imports = Vec::new();
        let trimmed_text = text.trim();

        // Only parse actual import statements, not string literals
        if trimmed_text.starts_with("from ") && trimmed_text.contains(" import ") {
            if let Some(from_start) = trimmed_text.find("from ") {
                if let Some(import_start) = trimmed_text.find(" import ") {
                    let module_part = &trimmed_text[from_start + 5..import_start].trim();
                    let import_part = &trimmed_text[import_start + 8..].trim();

                    // Clean up import part - remove parentheses and newlines
                    let cleaned_import_part = import_part
                        .replace('(', "")
                        .replace(')', "")
                        .replace('\n', " ")
                        .replace('\r', " ");

                    // Handle multiple imports: "from module import func1, func2"
                    for import in cleaned_import_part.split(',') {
                        let func_name = import.trim();
                        if !func_name.is_empty() &&
                           !func_name.starts_with('"') &&
                           !func_name.starts_with("'") &&
                           !func_name.contains("__") { // Skip __all__ etc
                            imports.push((func_name.to_string(), module_part.to_string()));
                        }
                    }
                }
            }
        }

        // Handle "import module" pattern (for module-level imports)
        if trimmed_text.starts_with("import ") && !trimmed_text.contains(" from ") {
            let module_part = &trimmed_text[7..].trim();
            if !module_part.is_empty() && !module_part.starts_with('"') && !module_part.starts_with("'") {
                // For module imports, we'll track the module name itself
                imports.push((module_part.to_string(), module_part.to_string()));
            }
        }

        if imports.is_empty() {
            None
        } else {
            Some(imports)
        }
    }





    /// Recursively trace taint from a sink variable/function back to sources across files - COMPLETELY REWRITTEN
    fn trace_taint_to_source(
        &self,
        start_file: &str,
        start_var: &str,
        visited: &mut std::collections::HashSet<(String, String)>,
        max_hops: usize,
        current_hops: usize,
    ) -> Option<(String, TaintSourceInfo, Vec<String>)> {
        let key = (start_file.to_string(), start_var.to_string());
        if visited.contains(&key) || current_hops >= max_hops {
            return None;
        }
        visited.insert(key.clone());

        // Strategy 1: Check if this variable/function is directly a taint source in this file
        if let Some(exports) = self.file_exports.get(start_file) {
            for source_info in &exports.taint_sources {
                // Check if the function name matches
                if &source_info.function == start_var {
                    return Some((start_file.to_string(), source_info.clone(), vec![start_file.to_string()]));
                }

                // Check if the variable might be related to this taint source
                if source_info.code.contains(start_var) || source_info.function.contains(start_var) {
                    return Some((start_file.to_string(), source_info.clone(), vec![start_file.to_string()]));
                }
            }
        }

        // Strategy 2: Check if this variable comes from a function call to an imported function
        if let Some(imports) = self.file_imports.get(start_file) {
            // Look for imported functions that might be the source of this variable
            for (imported_func, source_file) in &imports.functions {
                // Check if this imported function might be related to our variable
                if imported_func == start_var ||
                   start_var.contains(imported_func) ||
                   imported_func.contains("get_") ||  // Common taint source pattern
                   imported_func.contains("propagate_") {  // Common propagation pattern

                    // Recursively trace in the source file
                    if let Some((final_source_file, final_source_info, mut path)) =
                        self.trace_taint_to_source(source_file, imported_func, visited, max_hops, current_hops + 1) {
                        path.push(start_file.to_string());
                        return Some((final_source_file, final_source_info, path));
                    }
                }
            }
        }

        // Strategy 3: Look for any tainted functions in the export file that could be the source
        if let Some(imports) = self.file_imports.get(start_file) {
            for (imported_func, source_file) in &imports.functions {
                // Check if the source file has any taint sources
                if let Some(source_exports) = self.file_exports.get(source_file) {
                    for source_info in &source_exports.taint_sources {
                        // If this imported function contains taint sources, trace it
                        if &source_info.function == imported_func ||
                           source_info.function.contains("get_") ||
                           source_info.function.contains("env") ||
                           source_info.function.contains("arg") {

                            let path = vec![source_file.to_string(), start_file.to_string()];
                            return Some((source_file.to_string(), source_info.clone(), path));
                        }
                    }
                }
            }
        }

        // Strategy 4: Broad search - look for any functions that might propagate taint
        if let Some(imports) = self.file_imports.get(start_file) {
            for (imported_func, source_file) in &imports.functions {
                // For functions that might be propagating taint
                if imported_func.starts_with("propagate_") ||
                   imported_func.starts_with("get_") ||
                   imported_func.contains("config") ||
                   imported_func.contains("data") ||
                   imported_func.contains("env") {

                    // Check if the source file has taint sources
                    if let Some(source_exports) = self.file_exports.get(source_file) {
                        if !source_exports.taint_sources.is_empty() {
                            // Find the most relevant taint source
                            for source_info in &source_exports.taint_sources {
                                // Match by function name or by pattern relevance
                                if &source_info.function == imported_func ||
                                   source_info.function.contains("get_") ||
                                   source_info.function.contains("database") ||
                                   source_info.function.contains("config") ||
                                   source_info.function.contains("env") ||
                                   source_info.function.contains("arg") ||
                                   source_info.pattern.contains("os.environ") ||
                                   source_info.pattern.contains("sys.argv") {

                                    let path = vec![source_file.to_string(), start_file.to_string()];
                                    return Some((source_file.to_string(), source_info.clone(), path));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Strategy 5: Last resort - if we have any taint sources in imported files, use them
        if let Some(imports) = self.file_imports.get(start_file) {
            for (imported_func, source_file) in &imports.functions {
                if let Some(source_exports) = self.file_exports.get(source_file) {
                    if !source_exports.taint_sources.is_empty() {
                        // Use the first available taint source as a potential match
                        let source_info = &source_exports.taint_sources[0];
                        let path = vec![source_file.to_string(), start_file.to_string()];
                        return Some((source_file.to_string(), source_info.clone(), path));
                    }
                }
            }
        }

        None
    }

    /// Check if a function definition contains taint sources in its body - NEW function
    fn function_contains_taint_sources(
        func_node: &tree_sitter::Node,
        source: &[u8],
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> bool {
        // Recursively check all nodes in the function body
        let mut cursor = func_node.walk();
        if cursor.goto_first_child() {
            loop {
                let node = cursor.node();

                // Check if this node is a taint source
                if Self::extract_taint_source_pattern(&node, source, rule_deduplicator).is_some() {
                    return true;
                }

                // Recursively check children
                if Self::function_contains_taint_sources(&node, source, rule_deduplicator) {
                    return true;
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        false
    }
}


