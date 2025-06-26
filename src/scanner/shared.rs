use crate::language::LanguageSupport;
use crate::rules::{UnifiedRule, Rules, match_pattern, rule_matches_pattern_unified, check_for_injection_pattern, is_literal_node};
use crate::parser::{get_node_text, traverse_calls_only};
use super::types::{Finding, TraceStep};
use super::utils::rule_applies_to_file;
use super::conditions::check_ast_conditions;

/// Shared functionality for vulnerability scanning
pub struct ScanningLogic;

impl ScanningLogic {
    /// Check if rules have any patterns matching the function name (fast pre-filter)
    pub fn has_matching_rules(rules: &Rules, func_name: &str) -> bool {
        rules.get_search_rules().iter().any(|rule| rule_matches_pattern_unified(rule, func_name))
    }

    /// Get all search mode rules from a Rules struct as a flat vector
    pub fn get_all_search_rules(rules: &Rules) -> Vec<&UnifiedRule> {
        rules.get_search_rules()
    }

    /// Count total number of rules
    pub fn count_total_rules(rules: &Rules) -> usize {
        rules.count_rules()
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
                    let arg_text = get_node_text(&arg, source);
                    
                    // Skip if argument is a literal (low risk)
                    if is_literal_node(&arg) {
                        continue;
                    }
                    
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

    /// Add metadata from rule to finding
    pub fn add_finding_metadata(finding: &mut Finding, rule: &UnifiedRule, _node: &tree_sitter::Node) {
        finding.severity = rule.get_severity();
        finding.confidence = rule.get_confidence();
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
    ) -> Finding {
        Finding {
            file: file.to_string(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            end_line: node.end_position().row + 1,
            end_column: node.end_position().column + 1,
            function: function.to_string(),
            finding_type: finding_type.to_string(),
            severity: severity.to_string(),
            confidence: "Medium".to_string(),
            snippet: get_node_text(node, source),
            description: None,
            source_info: None,
            sink_info: None,
            traces: None,
            tags: None,
        }
    }

    /// Detect simple data flow traces by analyzing the current function scope
    fn detect_simple_traces(
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        _language_support: &dyn LanguageSupport,
    ) -> Vec<TraceStep> {
        let mut traces = Vec::new();
        
        // Find the containing function
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                // Look for variable assignments within this function
                Self::find_assignments_in_function(&parent, source, filepath, &mut traces);
                break;
            }
            current = parent.parent();
        }
        
        traces
    }

    /// Find variable assignments that could be part of a data flow
    fn find_assignments_in_function(
        func_node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        traces: &mut Vec<TraceStep>,
    ) {
        let mut cursor = func_node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                
                // Look for assignment expressions
                if child.kind() == "assignment" || child.kind() == "expression_statement" {
                    let assignment_text = get_node_text(&child, source);
                    
                    // Simple heuristic: if it contains = and looks like variable assignment
                    if assignment_text.contains('=') && !assignment_text.contains("==") {
                        if let Some(var_name) = Self::extract_assigned_variable(&assignment_text) {
                            traces.push(TraceStep {
                                file: filepath.to_string(),
                                line: child.start_position().row + 1,
                                code: assignment_text.trim().to_string(),
                                variable: var_name,
                                operation: "assignment".to_string(),
                                function: Self::get_function_context(&child, source),
                            });
                        }
                    }
                }
                
                // Recursively search child nodes
                Self::find_assignments_recursive(&child, source, filepath, traces);
                
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Recursively find assignments in nested nodes
    fn find_assignments_recursive(
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        traces: &mut Vec<TraceStep>,
    ) {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                
                if child.kind() == "assignment" {
                    let assignment_text = get_node_text(&child, source);
                    if let Some(var_name) = Self::extract_assigned_variable(&assignment_text) {
                        traces.push(TraceStep {
                            file: filepath.to_string(),
                            line: child.start_position().row + 1,
                            code: assignment_text.trim().to_string(),
                            variable: var_name,
                            operation: "assignment".to_string(),
                            function: Self::get_function_context(&child, source),
                        });
                    }
                }
                
                Self::find_assignments_recursive(&child, source, filepath, traces);
                
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Extract the variable name from an assignment expression
    fn extract_assigned_variable(assignment_text: &str) -> Option<String> {
        if let Some(equals_pos) = assignment_text.find('=') {
            let var_part = &assignment_text[..equals_pos];
            if let Some(var_name) = var_part.trim().split_whitespace().last() {
                return Some(var_name.to_string());
            }
        }
        None
    }

    /// Check a unified rule against a node and return a finding if it matches
    pub fn check_rule_against_node(
        rule: &UnifiedRule,
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        func_name: &str,
        language_support: &dyn LanguageSupport,
    ) -> Option<Finding> {
        // Check if the rule pattern matches
        if !rule_matches_pattern_unified(rule, func_name) {
            return None;
        }

        // Check file type restrictions
        if !rule_applies_to_file(rule.file_types.as_ref(), filepath) {
            return None;
        }

        // Check additional conditions if specified
        if let Some(conditions) = &rule.conditions {
            if !check_ast_conditions(conditions, node, source, language_support) {
                return None;
            }
        }

        // Check for injection patterns if this is an injection rule
        let is_injection_rule = rule.get_category() == "injection" || 
                               rule.get_finding_type().to_lowercase().contains("injection");

        if is_injection_rule {
            let has_injection = Self::has_injection_pattern(node, source, language_support);
            if !has_injection {
                return None;
            }
        }

        // Create and populate the finding
        let mut finding = Self::create_finding(
            filepath,
            node,
            func_name,
            &rule.get_finding_type(),
            source,
            &rule.get_severity(),
        );

        Self::add_finding_metadata(&mut finding, rule, node);

        // Detect source and sink information for taint-like analysis
        if let Some(source_info) = Self::detect_source_pattern(node, source, language_support) {
            finding.source_info = Some(source_info);
        }

        if let Some(sink_info) = Self::detect_sink_pattern(node, source, func_name, &rule.get_finding_type()) {
            finding.sink_info = Some(sink_info);
        }

        // Detect simple traces for data flow analysis
        let traces = Self::detect_simple_traces(node, source, filepath, language_support);
        if !traces.is_empty() {
            finding.traces = Some(traces);
        }

        Some(finding)
    }

    /// Scan a file with a list of unified rules
    pub fn scan_file_with_rules(
        filepath: &str,
        source: &[u8],
        tree: &tree_sitter::Tree,
        rules: &[&UnifiedRule],
        language_support: &dyn LanguageSupport,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Use the language-specific call traversal
        for node in traverse_calls_only(tree.root_node(), language_support) {
            if let Some(func_name) = language_support.get_function_name(&node, source) {
                for rule in rules {
                    if let Some(finding) = Self::check_rule_against_node(
                        rule,
                        &node,
                        source,
                        filepath,
                        &func_name,
                        language_support,
                    ) {
                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }

    /// Detect if a node represents a taint source
    fn detect_source_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        _language_support: &dyn LanguageSupport,
    ) -> Option<crate::scanner::types::SourceInfo> {
        let node_text = get_node_text(node, source);
        
        // Common source patterns that indicate user input or external data
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
                return Some(crate::scanner::types::SourceInfo {
                    source_type: source_type.to_string(),
                    location: format!("Line {}", node.start_position().row + 1),
                    context: Self::get_function_context(node, source),
                });
            }
        }

        None
    }

    /// Get the function context for better reporting
    fn get_function_context(node: &tree_sitter::Node, source: &[u8]) -> String {
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    return get_node_text(&name_node, source);
                }
            }
            current = parent.parent();
        }
        "unknown".to_string()
    }

    /// Detect if a node represents a taint sink
    fn detect_sink_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        func_name: &str,
        finding_type: &str,
    ) -> Option<crate::scanner::types::SinkInfo> {
        let node_text = get_node_text(node, source);
        
        // Determine sink category based on function name and finding type
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

        // Extract variable information if possible
        let variable = Self::extract_variable_from_text(&node_text);

        Some(crate::scanner::types::SinkInfo {
            sink_type: sink_category.to_string(),
            function_name: func_name.to_string(),
            location: format!("Line {}", node.start_position().row + 1),
            variable,
        })
    }

    /// Extract variable name from code text
    fn extract_variable_from_text(text: &str) -> Option<String> {
        // Simple extraction - look for assignment patterns
        if let Some(equals_pos) = text.find('=') {
            let before_equals = &text[..equals_pos];
            if let Some(var_name) = before_equals.split_whitespace().last() {
                return Some(var_name.to_string());
            }
        }
        
        // Look for function call patterns
        if let Some(paren_pos) = text.find('(') {
            let before_paren = &text[..paren_pos];
            if let Some(func_name) = before_paren.split_whitespace().last() {
                if let Some(dot_pos) = func_name.rfind('.') {
                    return Some(func_name[..dot_pos].to_string());
                } else {
                    return Some(func_name.to_string());
                }
            }
        }
        
        None
    }
} 