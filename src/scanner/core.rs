use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use walkdir::WalkDir;
use indicatif::{ProgressBar, ProgressStyle, ProgressDrawTarget};
use std::cell::RefCell;
use crate::parser::LanguageParser;
use memmap2::Mmap;
use std::fs::File;
use std::time::Duration;
use std::thread::JoinHandle;
use syntect::easy::HighlightLines;
use syntect::highlighting::{Style, ThemeSet};
use syntect::parsing::SyntaxSet;
use std::fs;

use crate::rules::Rules;

use crate::config::filters::SKIP_DIRS;

use crate::models::{Finding};

/// Helper struct for variable assignments
struct VariableAssignment {
    variable: String,
    value: String,
}

/// Taint rule deduplicator to prevent cartesian product problems
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
            if Self::matches_taint_pattern(pattern, text) {
                return Some(pattern.clone());
            }
        }
        None
    }
    
    /// Check if a pattern matches any sink  
    fn matches_sink_pattern(&self, text: &str) -> Option<String> {
        for pattern in &self.sink_patterns {
            if Self::matches_taint_pattern(pattern, text) {
                return Some(pattern.clone());
            }
        }
        None
    }
    
    /// Pattern matching logic (reusing existing implementation)
    fn matches_taint_pattern(pattern: &str, text: &str) -> bool {
        // Handle regex patterns from taint rules
        if pattern.contains("\\\\") || pattern.contains("\\.") {
            if let Ok(regex) = regex::Regex::new(pattern) {
                return regex.is_match(text);
            }
        }
        
        // Fallback to simple contains check for basic patterns
        text.contains(&pattern.replace("\\.", ".").replace("\\\\", "\\"))
    }
}

/// Shared functionality for vulnerability scanning (merged from shared.rs)
pub struct ScanningLogic;

impl ScanningLogic {
    /// Check if a rule matches against a specific node
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
            filepath,
            node,
            func_name,
            &rule.get_finding_type(),
            source,
            &rule.get_severity(),
        );

        Self::add_finding_metadata(&mut finding, rule, node);

        if let Some(source_info) = Self::detect_source_pattern(node, source, language_support) {
            finding.source_info = Some(source_info);
        }

        if let Some(sink_info) = Self::detect_sink_pattern(node, source, func_name, &rule.get_finding_type()) {
            finding.sink_info = Some(sink_info);
        }

        let traces = Self::detect_simple_traces(node, source, filepath, language_support);
        if !traces.is_empty() {
            finding.traces = Some(traces);
        }

        Some(finding)
    }

    /// Determine if a rule needs full context (node text) for pattern matching
    fn rule_needs_full_context(rule: &crate::rules::UnifiedRule) -> bool {
        if let Some(patterns) = &rule.patterns {
            for pattern in patterns {
                if pattern.contains('%') || pattern.contains('+') || pattern.contains("DROP") || 
                   pattern.contains("DELETE") || pattern.contains("UNION") || 
                   pattern.contains("innerHTML") || pattern.contains("outerHTML") ||
                   pattern.contains("location") || pattern.contains("postMessage") ||
                   pattern.contains("localStorage") || pattern.contains("sessionStorage") ||
                   pattern.contains("console.log") || pattern.contains("console.debug") ||
                   pattern.contains("fetch") || pattern.contains("axios") ||
                   pattern.contains("password") || pattern.contains("token") || 
                   pattern.contains("secret") || pattern.contains("key") ||
                   pattern.contains("http://") ||
                   pattern.contains("=") {
                    return true;
                }
            }
        }
        
        if let Some(pattern) = &rule.pattern {
            if pattern.contains('%') || pattern.contains('+') || pattern.contains("DROP") || 
               pattern.contains("DELETE") || pattern.contains("UNION") ||
               pattern.contains("innerHTML") || pattern.contains("outerHTML") ||
               pattern.contains("location") || pattern.contains("postMessage") ||
               pattern.contains("localStorage") || pattern.contains("sessionStorage") ||
               pattern.contains("console.log") || pattern.contains("console.debug") ||
               pattern.contains("fetch") || pattern.contains("axios") ||
               pattern.contains("password") || pattern.contains("token") || 
               pattern.contains("secret") || pattern.contains("key") ||
               pattern.contains("http://") ||
               pattern.contains("=") {
                return true;
            }
        }
        
        false
    }

    /// Determine if injection pattern checking should be applied
    fn should_check_injection_patterns(rule: &crate::rules::UnifiedRule) -> bool {
        rule.get_category() == "injection"
    }

    /// Scan a file with a list of unified rules
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

    /// Simplified assignment scanning using unified traversal
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
        
        if assignment_rules.is_empty() {
            return;
        }

        Self::scan_node_for_assignments(node, source, filepath, &assignment_rules, language_support, findings, processed_lines);
    }

    /// Simplified recursive assignment scanner
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
            
            if crate::common::CommonUtils::is_valid_assignment_text(&node_text) {
                let assignment_target = crate::common::CommonUtils::extract_variable_from_assignment(&node_text, true).unwrap_or_default();
        
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

    /// Check if a rule has assignment-related patterns (pre-filter at rule level)
    fn rule_has_assignment_patterns(rule: &crate::rules::UnifiedRule) -> bool {
        let patterns_to_check = if let Some(patterns) = &rule.patterns {
            patterns.as_slice()
        } else if let Some(pattern) = &rule.pattern {
            std::slice::from_ref(pattern)
        } else {
            return false;
        };

        patterns_to_check.iter().any(|pattern| {
            pattern.contains("innerHTML") || pattern.contains("outerHTML") ||
            pattern.contains("location") || pattern.contains("localStorage") ||
            pattern.contains("sessionStorage") || pattern.contains("__proto__") ||
            pattern.contains("=") || pattern.contains("prototype")
        })
    }

    /// Check if a rule might match assignment patterns (pre-filter)
    fn rule_might_match_assignment(rule: &crate::rules::UnifiedRule, node_text: &str) -> bool {
        if let Some(patterns) = &rule.patterns {
            for pattern in patterns {
                if pattern.contains("innerHTML") || pattern.contains("outerHTML") ||
                   pattern.contains("location") || pattern.contains("localStorage") ||
                   pattern.contains("sessionStorage") || pattern.contains("__proto__") ||
                   pattern.contains("=") {
                    if Self::quick_pattern_check(pattern, node_text) {
                        return true;
                    }
                }
            }
        }
        
        if let Some(pattern) = &rule.pattern {
            if pattern.contains("innerHTML") || pattern.contains("outerHTML") ||
               pattern.contains("location") || pattern.contains("localStorage") ||
               pattern.contains("sessionStorage") || pattern.contains("__proto__") ||
               pattern.contains("=") {
                return Self::quick_pattern_check(pattern, node_text);
            }
        }
        
        false
    }

    /// Quick pattern check (delegates to CommonUtils pattern matching)
    fn quick_pattern_check(pattern: &str, text: &str) -> bool {
        crate::common::CommonUtils::matches_pattern(pattern, text)
    }

    /// Detect if a node represents a taint source
    fn detect_source_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        _language_support: &dyn crate::language::LanguageSupport,
    ) -> Option<crate::models::SourceInfo> {
        let node_text = crate::parser::get_node_text(node, source);
        
        let source_patterns = [
            ("request", "HTTP Request"),
            ("input", "User Input"),
            ("sys.argv", "Command Line"),
            ("environ", "Environment Variable"),
            ("cookie", "HTTP Cookie"),
            ("header", "HTTP Header"),
            ("form", "Form Data"),
            ("query", "Query Parameter"),
            ("file", "File Input"),
            ("socket", "Network Socket"),
            ("subprocess", "External Process"),
            ("json.loads", "JSON Parsing"),
            ("pickle.loads", "Pickle Deserialization"),
            ("eval", "Dynamic Evaluation"),
            ("exec", "Dynamic Execution"),
        ];

        for (pattern, source_type) in &source_patterns {
            if node_text.contains(pattern) {
                return Some(crate::models::SourceInfo {
                    source_type: source_type.to_string(),
                    location: format!("Line {}", node.start_position().row + 1),
                    context: crate::scanner::utils::AstUtils::get_function_context(node, source),
                });
            }
        }

        None
    }

    /// Detect if a node represents a taint sink
    fn detect_sink_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        func_name: &str,
        finding_type: &str,
    ) -> Option<crate::models::SinkInfo> {
        let node_text = crate::parser::get_node_text(node, source);
        
        let sink_category = if finding_type.to_lowercase().contains("sql") {
            "Database Query"
        } else if finding_type.to_lowercase().contains("command") {
            "Command Execution"
        } else if finding_type.to_lowercase().contains("path") {
            "File System"
        } else if finding_type.to_lowercase().contains("xss") {
            "Web Output"
        } else {
            "General Sink"
        };

        let variable = Self::extract_variable_from_text(&node_text);

        Some(crate::models::SinkInfo {
            sink_type: sink_category.to_string(),
            function_name: func_name.to_string(),
            location: format!("Line {}", node.start_position().row + 1),
            variable,
        })
    }

    /// Extract variable name from code text (delegates to CommonUtils)
    fn extract_variable_from_text(text: &str) -> Option<String> {
        crate::common::CommonUtils::extract_variable_from_code_pattern(text)
    }

    /// Check if a rule should apply based on sanitization (uses unified sanitization checking)
    fn should_apply_rule_with_sanitization(rule: &crate::rules::UnifiedRule, node_text: &str) -> bool {
        if rule.get_finding_type().to_lowercase().contains("xss") || 
           rule.get_finding_type().to_lowercase().contains("dom") {
            return !crate::scanner::utils::AstUtils::check_for_sanitization(node_text, "javascript");
        }
        
        if rule.get_finding_type().to_lowercase().contains("prototype") {
            return node_text.contains("__proto__") || 
                   node_text.contains("['__proto__']") || 
                   node_text.contains("[\"__proto__\"]");
        }
        
        true
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
    
    /// Efficient pattern matching for function names
    fn pattern_might_match_function(pattern: &str, func_name: &str) -> bool {
        if pattern == func_name {
            return true;
        }
        
        if pattern.contains(func_name) || func_name.contains(pattern) {
            return true;
        }
        
        match pattern {
            p if p == "eval" => func_name == "eval",
            p if p == "Function" => func_name == "Function",
            p if p == "setTimeout" => func_name == "setTimeout",
            p if p == "setInterval" => func_name == "setInterval",
            p if p == "fetch" => func_name == "fetch",
            p if p == "Math.random" => func_name == "Math.random",
            p if p == "RegExp" => func_name == "RegExp",
            p if p == "import" => func_name == "import",
            p if p == "require" => func_name == "require",
            
            p if p.contains("document.write") => func_name.contains("document.write"),
            p if p.contains("console.") => func_name.contains("console"),
            p if p.contains("localStorage") => func_name.contains("localStorage"),
            p if p.contains("sessionStorage") => func_name.contains("sessionStorage"),
            p if p.contains("postMessage") => func_name.contains("postMessage"),
            p if p.contains("axios") => func_name.contains("axios"),
            
            p if p.contains('*') => Self::glob_match(p, func_name),
            
            _ => pattern.contains(func_name) || func_name.contains(pattern),
        }
    }
    
    /// Simple glob-style pattern matching (delegates to CommonUtils)
    fn glob_match(pattern: &str, text: &str) -> bool {
        crate::common::CommonUtils::matches_glob_pattern(pattern, text)
    }

    pub fn detect_simple_traces(
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        language_support: &dyn crate::language::LanguageSupport,
    ) -> Vec<crate::models::TraceStep> {
        // Implementation of the method
        Vec::new()
    }

    /// Check if rules have any patterns matching the function name (fast pre-filter)
    pub fn has_matching_rules(rules: &crate::rules::Rules, func_name: &str) -> bool {
        rules.get_search_rules().iter().any(|rule| crate::rules::rule_matches_pattern_unified(rule, func_name))
    }

    /// Get all search mode rules from a Rules struct as a flat vector
    pub fn get_all_search_rules(rules: &crate::rules::Rules) -> Vec<&crate::rules::UnifiedRule> {
        rules.get_search_rules()
    }

    /// Get all taint analysis rules
    pub fn get_all_taint_rules(rules: &crate::rules::Rules) -> Vec<&crate::rules::UnifiedRule> {
        rules.get_taint_rules()
    }

    /// Count total number of rules
    pub fn count_total_rules(rules: &crate::rules::Rules) -> usize {
        rules.count_rules()
    }

    /// Check if a node has injection patterns in its arguments
    pub fn has_injection_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        language_support: &dyn crate::language::LanguageSupport,
    ) -> bool {
        if let Some(args_node) = language_support.get_arguments_node(node) {
            for i in 0..args_node.named_child_count() {
                if let Some(arg) = args_node.named_child(i) {
                    let arg_text = crate::parser::get_node_text(&arg, source);
                    if crate::rules::is_literal_node(&arg) {
                        continue;
                    }
                    if crate::rules::check_for_injection_pattern(&arg_text, language_support) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Add metadata from rule to finding
    pub fn add_finding_metadata(finding: &mut crate::models::Finding, rule: &crate::rules::UnifiedRule, _node: &tree_sitter::Node) {
        finding.severity = rule.get_severity().to_string();
        finding.confidence = rule.get_confidence().to_string();
        finding.description = rule.description.clone();
        finding.tags = rule.tags.clone();
    }

    /// Create a basic finding
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
        Self::collect_all_relevant_nodes(tree.root_node(), &mut all_nodes);
        

        
        // Phase 1: Track variable assignments from taint sources
        for node in all_nodes.iter() {
            let node_text = crate::parser::get_node_text(node, source);
            let line = node.start_position().row + 1;
            let func_name = Self::get_containing_function_name(node, source);
            
            // Look for assignment patterns: var = source_call()
            if let Some(assignment) = Self::extract_assignment_from_node(&node_text) {
                // Check if the assignment value matches any taint source
                if let Some(source_pattern) = rule_deduplicator.matches_source_pattern(&assignment.value) {
                    
                    flow_tracker.record_tainted_variable(
                        assignment.variable.clone(),
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
        
        // Phase 2: Find sinks that use tainted variables
        for node in all_nodes.iter() {
            let node_text = crate::parser::get_node_text(node, source);
            let line = node.start_position().row + 1;
            let func_name = Self::get_containing_function_name(node, source);
            
            // Check if this node matches any sink pattern
            if let Some(sink_pattern) = rule_deduplicator.matches_sink_pattern(&node_text) {
                // Extract variables used in this sink
                if let Some(used_variable) = Self::extract_first_argument(&node_text) {
                    // Check if this variable is tainted (clone to avoid borrowing conflicts)
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

    /// Extract assignment from node text (reusing DRY principle)
    fn extract_assignment_from_node(text: &str) -> Option<VariableAssignment> {
        // Look for patterns: variable = source_pattern
        if let Some(eq_pos) = text.find('=') {
            let left = text[..eq_pos].trim();
            let right = text[eq_pos + 1..].trim();
            
            // Get the variable name (last identifier on left side)
            if let Some(var_name) = left.split_whitespace().last() {
                // Filter out comparison operators  
                if !var_name.contains("==") && !var_name.contains("!=") && 
                   !var_name.contains("<=") && !var_name.contains(">=") {
                    return Some(VariableAssignment {
                        variable: var_name.to_string(),
                        value: right.to_string(),
                    });
                }
            }
        }
        None
    }
    
    /// Extract first argument from function call (reusing existing patterns)
    fn extract_first_argument(text: &str) -> Option<String> {
        if let Some(start) = text.find('(') {
            if let Some(end) = text.rfind(')') {
                let args = &text[start + 1..end];
                if let Some(first_arg) = args.split(',').next() {
                    let cleaned = first_arg.trim();
                    // Only return if it looks like a variable (not a string literal)
                    if !cleaned.is_empty() && 
                       !cleaned.starts_with('"') && 
                       !cleaned.starts_with('\'') &&
                       !cleaned.starts_with('/') &&
                       !cleaned.chars().all(|c| c.is_numeric()) {
                        return Some(cleaned.to_string());
                    }
                }
            }
        }
        None
    }

    /// Get containing function name from node
    fn get_containing_function_name(node: &tree_sitter::Node, source: &[u8]) -> String {
        let mut current = *node;
        
        // Traverse up to find function definition
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_definition" {
                // Find the function name
                let mut cursor = parent.walk();
                if cursor.goto_first_child() {
                    loop {
                        if cursor.node().kind() == "identifier" {
                            return crate::parser::get_node_text(&cursor.node(), source);
                        }
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
            current = parent;
        }
        
        "global".to_string()
    }

    /// Collect all relevant nodes for taint analysis (assignments and calls)
    fn collect_all_relevant_nodes<'a>(node: tree_sitter::Node<'a>, nodes: &mut Vec<tree_sitter::Node<'a>>) {
        // Include assignment and call nodes
        match node.kind() {
            "assignment" | "call" | "expression_statement" | "assignment_expression" => {
                nodes.push(node);
            }
            _ => {}
        }
        
        // Recursively traverse children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                Self::collect_all_relevant_nodes(cursor.node(), nodes);
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

thread_local! {
    // Store (language_name, parser) so we can reuse per language inside each thread
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

    /// Unified vulnerability scanner that handles both search and taint analysis rules
    /// Reuses all existing infrastructure for maximum performance
    pub fn find_vulnerabilities_unified(&self, root_dir: &str, language_name: &str, show_progress: bool) -> Result<Vec<Finding>> {
        // Use multi-language file discovery for comprehensive analysis
        let files_by_language = if self.language.is_empty() {
            // Multi-language discovery for auto-detection mode (default to parallel)
            crate::scanner::utils::discover_files_by_language(root_dir, true)?
        } else {
            // Single language discovery for explicit mode
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

        // Flatten all files for unified processing
        let all_files: Vec<std::path::PathBuf> = files_by_language.values().flatten().cloned().collect();
        
        if all_files.is_empty() {
            if show_progress {
                println!("No files found after discovery");
            }
            return Ok(Vec::new());
        }

        // Apply same pre-filtering as search mode
        let prefilter = crate::scanner::prefilter::PreFilter::with_options(
            &self.rules, 
            language_name, 
            self.skip_minified, 
            Vec::new()
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

        // Get both rule types (reuse existing infrastructure)
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

        // Reuse existing progress management infrastructure
        let mut progress_manager = if show_progress { 
            Some(ProgressManager::new(filtered_files.len())) 
        } else { 
            None 
        };
        let total_findings = Arc::new(AtomicUsize::new(0));
        let chunk_size = crate::config::ScanDefaults::CHUNK_SIZE;

        use rayon::slice::ParallelSlice;

        let processed = Arc::new(AtomicUsize::new(0));
        
        // Start progress tracking (reuse existing infrastructure)
        if let Some(ref mut progress) = progress_manager {
            progress.start_tracking(Arc::clone(&processed), Arc::clone(&total_findings));
        }

        // Reuse exact same parallel processing pattern as search mode
        let findings: Vec<Finding> = filtered_files
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
                                            
                                            // Taint mode findings (new functionality, reuses infrastructure)
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

        // Stop progress tracking (reuse existing infrastructure)
        if let Some(mut progress) = progress_manager {
            progress.stop();
        }
        
        if show_progress {
            let search_count = findings.iter().filter(|f| {
                f.tags.as_ref().map_or(true, |tags| !tags.contains(&"taint_analysis".to_string()))
            }).count();
            let taint_count = findings.len() - search_count;
            
            if has_search_rules && has_taint_rules {
                println!("Found {} search findings and {} taint flows", search_count, taint_count);
            } else if has_search_rules {
                println!("Found {} search findings", search_count);
            } else {
                println!("Found {} taint flows", taint_count);
            }
        }
        
        Ok(findings)
    }
}

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
                let syntax_name = crate::common::CommonUtils::detect_syntax(&finding.file);
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

/// Variable flow tracker for legitimate taint analysis
#[derive(Debug)]
struct VariableFlowTracker {
    /// Maps variable names to their taint source information
    tainted_variables: std::collections::HashMap<String, TaintVariableInfo>,
    /// Function scopes to handle variable visibility
    function_scopes: std::collections::HashMap<String, std::collections::HashSet<String>>,
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
    
    /// Check if variable is likely global/passed between functions (reusing existing logic)
    fn is_global_variable(var_name: &str) -> bool {
        // Simple heuristics for global variables
        var_name.to_uppercase() == var_name || // ALL_CAPS
        var_name.starts_with("app.") ||        // app.something
        var_name.contains("_DIR") ||           // paths
        var_name.contains("_PATH")             // paths
    }
}