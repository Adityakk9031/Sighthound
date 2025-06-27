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
        let vulnerability_line = node.start_position().row + 1;
        
        // Extract variables used in the vulnerability
        let vulnerability_text = get_node_text(node, source);
        let used_variables = Self::extract_variables_from_code(&vulnerability_text);
        
        // Find the containing function
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                // Look for assignments of the variables used in the vulnerability
                Self::find_relevant_variable_assignments(&parent, source, filepath, vulnerability_line, &used_variables, &mut traces);
                break;
            }
            current = parent.parent();
        }
        
        traces
    }

    /// Extract variable names from code text
    fn extract_variables_from_code(code: &str) -> Vec<String> {
        let mut variables = Vec::new();
        
        // Simple regex-like extraction of identifiers
        let words: Vec<&str> = code.split(|c: char| !c.is_alphanumeric() && c != '_')
            .filter(|w| !w.is_empty() && w.chars().next().unwrap().is_alphabetic())
            .collect();
        
        for word in words {
            // Skip common keywords and built-ins
            if !matches!(word, "cursor" | "execute" | "SELECT" | "FROM" | "WHERE" | "AND" | "OR" | 
                        "if" | "else" | "try" | "except" | "for" | "while" | "def" | "class" | 
                        "import" | "from" | "as" | "with" | "return" | "yield" | "pass" | "break" | "continue" |
                        "True" | "False" | "None" | "str" | "int" | "float" | "list" | "dict" | "set" | "tuple") {
                if !variables.contains(&word.to_string()) {
                    variables.push(word.to_string());
                }
            }
        }
        
        variables
    }

    /// Find assignments of variables that are actually used in the vulnerability
    fn find_relevant_variable_assignments(
        func_node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        vulnerability_line: usize,
        used_variables: &[String],
        traces: &mut Vec<TraceStep>,
    ) {
        let mut cursor = func_node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                let child_line = child.start_position().row + 1;
                
                // Only process nodes that occur before the vulnerability
                if child_line < vulnerability_line {
                    Self::check_node_for_relevant_assignments(&child, source, filepath, used_variables, traces, vulnerability_line);
                }
                
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        // Remove duplicates and sort by line number
        traces.sort_by_key(|t| (t.line, t.variable.clone()));
        traces.dedup_by(|a, b| a.line == b.line && a.variable == b.variable);
    }

    /// Check a node and its children for assignments of relevant variables
    fn check_node_for_relevant_assignments(
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        used_variables: &[String],
        traces: &mut Vec<TraceStep>,
        vulnerability_line: usize,
    ) {
        let node_line = node.start_position().row + 1;
        
        // Only process nodes that occur before the vulnerability
        if node_line >= vulnerability_line {
            return;
        }
        
        // Check if this node is an assignment
        if node.kind() == "assignment" || node.kind() == "expression_statement" {
            let assignment_text = get_node_text(node, source);
            
            // Check if it's a variable assignment (contains = but not == or !=)
            if assignment_text.contains('=') && 
               !assignment_text.contains("==") && 
               !assignment_text.contains("!=") &&
               !assignment_text.contains("<=") &&
               !assignment_text.contains(">=") {
                
                if let Some(var_name) = Self::extract_assigned_variable(&assignment_text) {
                    // Only include if this variable is used in the vulnerability
                    if used_variables.contains(&var_name) {
                        traces.push(TraceStep {
                            file: filepath.to_string(),
                            line: node_line,
                            code: assignment_text.trim().to_string(),
                            variable: var_name,
                            operation: "assignment".to_string(),
                            function: Self::get_function_context(node, source),
                        });
                    }
                }
            }
        }
        
        // Recursively check child nodes
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                Self::check_node_for_relevant_assignments(&child, source, filepath, used_variables, traces, vulnerability_line);
                
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

    /// Check if a rule matches against a specific node
    pub fn check_rule_against_node(
        rule: &UnifiedRule,
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        func_name: &str,
        language_support: &dyn LanguageSupport,
    ) -> Option<Finding> {
        let pattern_matches = if Self::rule_needs_full_context(rule) {
            let node_text = get_node_text(node, source);
            rule_matches_pattern_unified(rule, &node_text)
        } else {
            rule_matches_pattern_unified(rule, func_name)
        };

        if !pattern_matches {
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

        // For JavaScript, check sanitization patterns
        if language_support.name() == "javascript" || language_support.name() == "typescript" {
            let node_text = get_node_text(node, source);
            if !Self::should_apply_rule_with_sanitization(rule, &node_text) {
                return None;
            }
        }

        // Check injection patterns only for rules that need it
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

    /// Determine if a rule needs full context (node text) for pattern matching
    fn rule_needs_full_context(rule: &UnifiedRule) -> bool {
        // Check if any patterns contain operators that would be in the full expression
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
    fn should_check_injection_patterns(rule: &UnifiedRule) -> bool {
        // Only apply strict injection checking to rules explicitly marked as "injection" category
        // Allow database rules to have their own validation logic
        rule.get_category() == "injection"
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
        let mut processed_lines = std::collections::HashSet::new();

        // Use the language-specific call traversal for function calls
        let call_nodes: Vec<_> = traverse_calls_only(tree.root_node(), language_support).collect();
        
        for node in call_nodes.iter() {
            if let Some(func_name) = language_support.get_function_name(node, source) {
                // Pre-filter rules to only check those that might match
                let relevant_rules: Vec<(usize, &UnifiedRule)> = rules.iter().enumerate()
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

        // For JavaScript/TypeScript, also scan assignment expressions
        if language_support.name() == "javascript" || language_support.name() == "typescript" {
            Self::scan_assignments(tree.root_node(), source, filepath, rules, language_support, &mut findings, &mut processed_lines);
        }

        findings
    }

    /// Scan assignment expressions for JavaScript/TypeScript patterns
    fn scan_assignments(
        node: tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        rules: &[&UnifiedRule],
        language_support: &dyn LanguageSupport,
        findings: &mut Vec<Finding>,
        processed_lines: &mut std::collections::HashSet<(usize, String, String)>,
    ) {
        // Only check specific node types that are likely to be assignments
        match node.kind() {
            "assignment_expression" | "expression_statement" => {
                let node_text = get_node_text(&node, source);
                
                // Quick check: must contain '=' but not comparison operators
                if node_text.contains('=') && 
                   !node_text.contains("==") && 
                   !node_text.contains("!=") &&
                   !node_text.contains("<=") &&
                   !node_text.contains(">=") {
                    
                    // Pre-filter rules: only check rules that might match assignment patterns
                    let relevant_rules: Vec<&UnifiedRule> = rules.iter()
                        .filter(|rule| Self::rule_might_match_assignment(rule, &node_text))
                        .copied()
                        .collect();
                    
                    if !relevant_rules.is_empty() {
                        // Extract the left side of the assignment as the "function name"
                        let assignment_target = if let Some(equals_pos) = node_text.find('=') {
                            node_text[..equals_pos].trim()
                        } else {
                            ""
                        };

                        // Check only relevant rules against this assignment
                        for rule in relevant_rules {
                            if let Some(finding) = Self::check_rule_against_node(
                                rule,
                                &node,
                                source,
                                filepath,
                                assignment_target,
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
            }
            // Only traverse into nodes that might contain assignments
            "program" | "statement_block" | "compound_statement" | "block_statement" | 
            "function_declaration" | "function_definition" | "method_definition" |
            "if_statement" | "for_statement" | "while_statement" | "try_statement" => {
                // Recursively scan child nodes for these container types
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        Self::scan_assignments(cursor.node(), source, filepath, rules, language_support, findings, processed_lines);
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
            _ => {
                // For other node types, don't traverse deeper to avoid unnecessary work
            }
        }
    }

    /// Check if a rule might match assignment patterns (pre-filter)
    fn rule_might_match_assignment(rule: &UnifiedRule, node_text: &str) -> bool {
        // Check if the rule has patterns that could match assignments
        if let Some(patterns) = &rule.patterns {
            for pattern in patterns {
                // Check for assignment-related patterns
                if pattern.contains("innerHTML") || pattern.contains("outerHTML") ||
                   pattern.contains("location") || pattern.contains("localStorage") ||
                   pattern.contains("sessionStorage") || pattern.contains("__proto__") ||
                   pattern.contains("=") {
                    // Quick text check to see if this pattern might match
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

    /// Quick pattern check without full regex matching
    fn quick_pattern_check(pattern: &str, text: &str) -> bool {
        // Simple substring checks for common patterns
        if pattern.contains("innerHTML") && text.contains("innerHTML") {
            return true;
        }
        if pattern.contains("outerHTML") && text.contains("outerHTML") {
            return true;
        }
        if pattern.contains("location") && text.contains("location") {
            return true;
        }
        if pattern.contains("localStorage") && text.contains("localStorage") {
            return true;
        }
        if pattern.contains("sessionStorage") && text.contains("sessionStorage") {
            return true;
        }
        if pattern.contains("__proto__") && text.contains("__proto__") {
            return true;
        }
        
        false
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

    /// Check for sanitization patterns in JavaScript code
    fn check_javascript_sanitization(node_text: &str) -> bool {
        let sanitization_patterns = [
            "DOMPurify.sanitize",
            "sanitize(",
            ".textContent",
            ".innerText",
            "encodeURIComponent",
            "encodeURI",
            "escape(",
            "validator.escape",
            "xss(",
        ];
        
        for pattern in &sanitization_patterns {
            if node_text.contains(pattern) {
                return true;
            }
        }
        
        false
    }

    /// Check if a rule should apply based on sanitization
    fn should_apply_rule_with_sanitization(rule: &UnifiedRule, node_text: &str) -> bool {
        // For XSS rules, check for sanitization
        if rule.get_finding_type().to_lowercase().contains("xss") || 
           rule.get_finding_type().to_lowercase().contains("dom") {
            return !Self::check_javascript_sanitization(node_text);
        }
        
        // For prototype pollution, be more specific
        if rule.get_finding_type().to_lowercase().contains("prototype") {
            return node_text.contains("__proto__") || 
                   node_text.contains("['__proto__']") || 
                   node_text.contains("[\"__proto__\"]");
        }
        
        true
    }

    /// Check if a rule might match the function name (pre-filter)
    fn rule_might_match_function(rule: &UnifiedRule, func_name: &str) -> bool {
        // Check if the rule has patterns that could match the function name
        if let Some(patterns) = &rule.patterns {
            for pattern in patterns {
                // Simple substring match for exact function names
                if pattern.contains(func_name) {
                    return true;
                }
                
                // Handle common cases where pattern might match
                if func_name == "eval" && pattern.contains("eval") {
                    return true;
                }
                if func_name == "Function" && pattern.contains("Function") {
                    return true;
                }
                if func_name == "setTimeout" && pattern.contains("setTimeout") {
                    return true;
                }
                if func_name == "setInterval" && pattern.contains("setInterval") {
                    return true;
                }
                if func_name.contains("document.write") && pattern.contains("document.write") {
                    return true;
                }
                if func_name.contains("localStorage") && pattern.contains("localStorage") {
                    return true;
                }
                if func_name.contains("sessionStorage") && pattern.contains("sessionStorage") {
                    return true;
                }
                if func_name.contains("postMessage") && pattern.contains("postMessage") {
                    return true;
                }
                if func_name.contains("console") && pattern.contains("console") {
                    return true;
                }
                if func_name == "fetch" && pattern.contains("fetch") {
                    return true;
                }
                if func_name.contains("axios") && pattern.contains("axios") {
                    return true;
                }
                if func_name == "Math.random" && pattern.contains("Math.random") {
                    return true;
                }
                if func_name == "RegExp" && pattern.contains("RegExp") {
                    return true;
                }
                if func_name == "import" && pattern.contains("import") {
                    return true;
                }
                if func_name == "require" && pattern.contains("require") {
                    return true;
                }
            }
        }
        
        if let Some(pattern) = &rule.pattern {
            // Same checks for single pattern
            if pattern.contains(func_name) ||
               (func_name == "eval" && pattern.contains("eval")) ||
               (func_name == "Function" && pattern.contains("Function")) ||
               (func_name == "setTimeout" && pattern.contains("setTimeout")) ||
               (func_name == "setInterval" && pattern.contains("setInterval")) ||
               (func_name.contains("document.write") && pattern.contains("document.write")) ||
               (func_name.contains("localStorage") && pattern.contains("localStorage")) ||
               (func_name.contains("sessionStorage") && pattern.contains("sessionStorage")) ||
               (func_name.contains("postMessage") && pattern.contains("postMessage")) ||
               (func_name.contains("console") && pattern.contains("console")) ||
               (func_name == "fetch" && pattern.contains("fetch")) ||
               (func_name.contains("axios") && pattern.contains("axios")) ||
               (func_name == "Math.random" && pattern.contains("Math.random")) ||
               (func_name == "RegExp" && pattern.contains("RegExp")) ||
               (func_name == "import" && pattern.contains("import")) ||
               (func_name == "require" && pattern.contains("require")) {
                return true;
            }
        }
        
        false
    }
} 