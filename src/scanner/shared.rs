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
        
        // Convert unified rules to legacy format for compatibility
        if let Some(unified_rules) = &rules.rules {
            for unified_rule in unified_rules {
                // Only include search mode rules (pattern matching)
                if unified_rule.is_search_rule() {
                    all_rules.push(Self::convert_unified_to_legacy_rule(unified_rule));
                }
            }
        }
        
        // Include legacy rules
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
    
    /// Convert a UnifiedRule to legacy Rule format for pattern matching
    fn convert_unified_to_legacy_rule(unified_rule: &crate::rules::UnifiedRule) -> Rule {
        Rule {
            pattern: unified_rule.pattern.clone(),
            patterns: unified_rule.patterns.clone(),
            finding_type: unified_rule.finding_type.clone(),
            conditions: unified_rule.conditions.clone(),
            file_types: unified_rule.file_types.clone(),
            severity: unified_rule.severity.clone(),
            confidence: unified_rule.confidence.clone(),
            sanitizers: unified_rule.sanitizers.clone(),
        }
    }

    /// Count total number of rules across all categories (unified + legacy)
    pub fn count_total_rules(rules: &Rules) -> usize {
        let mut count = 0;
        
        // Count unified rules
        if let Some(unified_rules) = &rules.rules {
            count += unified_rules.len();
        }
        
        // Count legacy rules
        if let Some(rules_vec) = &rules.injection_sinks { count += rules_vec.len(); }
        if let Some(rules_vec) = &rules.crypto_rules { count += rules_vec.len(); }
        if let Some(rules_vec) = &rules.path_traversal { count += rules_vec.len(); }
        if let Some(rules_vec) = &rules.weak_random { count += rules_vec.len(); }
        if let Some(rules_vec) = &rules.hardcoded_secrets { count += rules_vec.len(); }
        if let Some(rules_vec) = &rules.malware_detection { count += rules_vec.len(); }
        if let Some(rules_vec) = &rules.taint_flows { count += rules_vec.len(); }
        
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
            source: None,
            sink: None,
        }
    }

    /// Create a finding with source and sink information
    pub fn create_finding_with_source_sink(
        file: &str,
        node: &tree_sitter::Node,
        function: &str,
        finding_type: &str,
        source: &[u8],
        severity: &str,
        source_info: Option<crate::scanner::types::SourceInfo>,
        sink_info: Option<crate::scanner::types::SinkInfo>,
    ) -> Finding {
        Finding {
            file: file.to_string(),
            line: node.start_position().row + 1,
            function: function.to_string(),
            finding_type: finding_type.to_string(),
            code: get_node_text(node, source).trim().to_string(),
            severity: severity.to_string(),
            source: source_info,
            sink: sink_info,
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
        
        // Detect source and sink patterns
        let source_info = Self::detect_source_pattern(node, source, language_support);
        let sink_info = Self::detect_sink_pattern(node, source, func_name, finding_type);
        
        // Create the finding with source/sink information
        let mut finding = if source_info.is_some() || sink_info.is_some() {
            Self::create_finding_with_source_sink(filepath, node, func_name, finding_type, source, severity, source_info, sink_info)
        } else {
            Self::create_finding(filepath, node, func_name, finding_type, source, severity)
        };
        
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

    /// Detect if a node represents a source pattern (user input, etc.)
    fn detect_source_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        _language_support: &dyn LanguageSupport,
    ) -> Option<crate::scanner::types::SourceInfo> {
        // First check the immediate node
        let node_text = get_node_text(node, source);
        
        // Also check the broader function context to find sources
        let function_context = Self::get_function_context(node, source);
        let combined_text = format!("{}\n{}", function_context, node_text);
        
        // Common source patterns
        let source_patterns = [
            ("request.args.get", "web_request"),
            ("request.form.get", "web_request"),
            ("request.json.get", "web_request"),
            ("request.get", "web_request"),
            ("request.POST", "web_request"),
            ("input(", "user_input"),
            ("raw_input(", "user_input"),
            ("sys.argv", "command_line"),
            ("os.environ.get", "environment"),
            ("os.getenv", "environment"),
            ("getenv", "environment"),
            ("$_GET", "web_request"),
            ("$_POST", "web_request"),
            ("$_REQUEST", "web_request"),
            ("System.getenv", "environment"),
            ("Scanner.nextLine", "user_input"),
        ];
        
        // Check both immediate node and function context
        for (pattern, source_type) in &source_patterns {
            if combined_text.contains(pattern) {
                let variable = Self::extract_variable_from_text(&combined_text);
                return Some(crate::scanner::types::SourceInfo {
                    pattern: pattern.to_string(),
                    variable,
                    operation: source_type.to_string(),
                });
            }
        }
        
        None
    }

    /// Get the broader function context for source detection
    fn get_function_context(node: &tree_sitter::Node, source: &[u8]) -> String {
        // Find the containing function
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" || parent.kind() == "method_definition" {
                return get_node_text(&parent, source);
            }
            current = parent.parent();
        }
        
        // If no function found, return empty string
        String::new()
    }

    /// Detect if a node represents a sink pattern (dangerous function call, etc.)
    fn detect_sink_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        func_name: &str,
        finding_type: &str,
    ) -> Option<crate::scanner::types::SinkInfo> {
        let node_text = get_node_text(node, source);
        
        // Determine sink type based on function name and finding type
        let (_sink_type, operation) = if finding_type.contains("sql") || finding_type.contains("SQL") {
            ("sql_execution", "database_query")
        } else if finding_type.contains("command") || finding_type.contains("injection") {
            ("command_execution", "system_command")
        } else if finding_type.contains("xss") || finding_type.contains("XSS") {
            ("html_output", "dom_manipulation")
        } else if finding_type.contains("crypto") || finding_type.contains("hash") {
            ("cryptographic", "hashing")
        } else if finding_type.contains("file") || finding_type.contains("path") {
            ("file_operation", "file_access")
        } else {
            ("generic_sink", "function_call")
        };
        
        // Common sink patterns
        let sink_patterns = [
            // SQL execution
            ("execute", "sql_execution"),
            ("cursor.execute", "sql_execution"),
            ("query", "sql_execution"),
            // Command execution
            ("os.system", "command_execution"),
            ("subprocess.call", "command_execution"),
            ("subprocess.run", "command_execution"),
            ("exec", "command_execution"),
            ("eval", "code_execution"),
            // File operations
            ("open(", "file_operation"),
            ("os.path.join", "path_operation"),
            // Crypto
            ("hashlib.md5", "weak_crypto"),
            ("hashlib.sha1", "weak_crypto"),
            ("DES.new", "weak_crypto"),
            ("ARC4.new", "weak_crypto"),
        ];
        
        for (pattern, detected_type) in &sink_patterns {
            if node_text.contains(pattern) || func_name.contains(pattern) {
                let variable = Self::extract_variable_from_text(&node_text);
                return Some(crate::scanner::types::SinkInfo {
                    pattern: pattern.to_string(),
                    variable,
                    operation: detected_type.to_string(),
                });
            }
        }
        
        // If we have a finding type but no specific pattern, create a generic sink
        if !finding_type.is_empty() && finding_type != "vulnerability" {
            let variable = Self::extract_variable_from_text(&node_text);
            return Some(crate::scanner::types::SinkInfo {
                pattern: func_name.to_string(),
                variable,
                operation: operation.to_string(),
            });
        }
        
        None
    }

    /// Extract variable name from node text
    fn extract_variable_from_text(text: &str) -> Option<String> {
        // Look for assignment patterns like "var = ..." or "var.method(...)"
        if let Some(eq_pos) = text.find('=') {
            let left_side = text[..eq_pos].trim();
            if let Some(var_name) = left_side.split_whitespace().last() {
                return Some(var_name.to_string());
            }
        }
        
        // Look for method call patterns like "object.method(...)"
        if let Some(dot_pos) = text.find('.') {
            let left_side = text[..dot_pos].trim();
            if let Some(var_name) = left_side.split_whitespace().last() {
                return Some(var_name.to_string());
            }
        }
        
        // Look for function call patterns like "function(...)"
        if let Some(paren_pos) = text.find('(') {
            let func_part = text[..paren_pos].trim();
            if let Some(func_name) = func_part.split_whitespace().last() {
                return Some(func_name.to_string());
            }
        }
        
        None
    }

    pub fn print_rules_summary(&self, rules: &Rules) {
        println!("📋 Rules Summary:");
        if let Some(rules_vec) = &rules.injection_sinks {
            println!("   • Injection Sinks: {}", rules_vec.len());
        }
        if let Some(rules_vec) = &rules.crypto_rules {
            println!("   • Crypto Rules: {}", rules_vec.len());
        }
        if let Some(rules_vec) = &rules.path_traversal {
            println!("   • Path Traversal: {}", rules_vec.len());
        }
        if let Some(rules_vec) = &rules.weak_random {
            println!("   • Weak Random: {}", rules_vec.len());
        }
        if let Some(rules_vec) = &rules.hardcoded_secrets {
            println!("   • Hardcoded Secrets: {}", rules_vec.len());
        }
        if let Some(rules_vec) = &rules.malware_detection {
            println!("   • Malware Detection: {}", rules_vec.len());
        }
        if let Some(rules_vec) = &rules.taint_flows {
            println!("   • Taint Flows: {}", rules_vec.len());
        }
        
        // Print other rule categories
        for (category, rules_vec) in &rules.other {
            println!("   • {}: {}", category, rules_vec.len());
        }
    }
} 