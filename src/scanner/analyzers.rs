use anyhow::Result;
use std::path::Path;
use std::collections::HashMap;
use crate::language::LanguageSupport;
use crate::rules::{Rule, Rules, Condition};
use crate::{traverse_calls_only, match_pattern, get_node_text_slice, check_for_injection_pattern};
use super::types::{Finding, ScanContext, FilteringStats};

pub struct FileTypeAwareAnalyzer {
    language_support: Box<dyn LanguageSupport>,
    rules: Rules,
    rules_by_extension: HashMap<String, Vec<Rule>>,
    stats: FilteringStats,
}

impl FileTypeAwareAnalyzer {
    pub fn new(
        language_support: Box<dyn LanguageSupport>,
        rules: Rules,
    ) -> Result<Self> {
        Ok(Self {
            language_support,
            rules,
            rules_by_extension: HashMap::new(),
            stats: FilteringStats::new(),
        })
    }

    pub fn get_stats(&self) -> &FilteringStats {
        &self.stats
    }

    pub fn scan_with_filtering(&mut self, context: &ScanContext) -> Result<Vec<Finding>> {
        self.stats.total_files += 1;
        
        // Get file extension and info
        let file_path = Path::new(&context.filepath);
        let _extension = file_path.extension().and_then(|s| s.to_str()).unwrap_or("");
        
        // Get applicable rules for this file type
        let applicable_rules = self.get_applicable_rules(file_path, &context.source);
        
        self.stats.files_processed += 1;
        self.stats.total_rules_checked += self.count_total_rules();
        self.stats.applicable_rules_found += applicable_rules.len();

        // Scan only with applicable rules
        self.scan_with_rules(context, applicable_rules)
    }

    fn get_applicable_rules(&mut self, file_path: &Path, _source: &[u8]) -> Vec<Rule> {
        let extension = file_path.extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Check cache first
        if let Some(cached_rules) = self.rules_by_extension.get(&extension) {
            self.stats.cache_hits += 1;
            return cached_rules.clone();
        }

        // Collect all rules first to avoid borrow issues
        let mut all_rules = Vec::new();
        
        if let Some(rules) = &self.rules.injection_sinks {
            all_rules.extend(rules.iter().cloned());
        }
        if let Some(rules) = &self.rules.crypto_rules {
            all_rules.extend(rules.iter().cloned());
        }
        if let Some(rules) = &self.rules.path_traversal {
            all_rules.extend(rules.iter().cloned());
        }
        if let Some(rules) = &self.rules.weak_random {
            all_rules.extend(rules.iter().cloned());
        }
        if let Some(rules) = &self.rules.hardcoded_secrets {
            all_rules.extend(rules.iter().cloned());
        }
        if let Some(rules) = &self.rules.malware_detection {
            all_rules.extend(rules.iter().cloned());
        }

        // Filter rules by file type
        let mut applicable_rules = Vec::new();
        for rule in all_rules {
            if self.rule_applies_to_file(&rule, file_path) {
                applicable_rules.push(rule);
                self.stats.extension_filters_applied += 1;
            }
        }

        // Cache the result
        self.rules_by_extension.insert(extension, applicable_rules.clone());
        applicable_rules
    }

    fn rule_applies_to_file(&self, rule: &Rule, file_path: &Path) -> bool {
        // If rule has file_types filter, check it
        if let Some(file_types) = self.get_rule_file_types(rule) {
            let extension = file_path.extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            
            return file_types.extensions.contains(&extension);
        }
        
        // If no file type filter, rule applies to all files
        true
    }

    fn get_rule_file_types<'a>(&self, rule: &'a Rule) -> Option<&'a crate::rules::FileTypeFilter> {
        rule.file_types.as_ref()
    }

    fn scan_with_rules(&mut self, context: &ScanContext, rules: Vec<Rule>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let root_node = context.tree.root_node();
        
        for node in traverse_calls_only(root_node, self.language_support.as_ref()) {
            if let Some(func_name) = self.language_support.get_function_name(&node, &context.source) {
                for rule in &rules {
                    if match_pattern(&rule.pattern, func_name) {
                        let finding_type = rule.finding_type.as_deref().unwrap_or("vulnerability");
                        if let Some(conditions) = &rule.conditions {
                            if self.check_ast_conditions(&node, &context.source, conditions) {
                                findings.push(self.create_finding(&context.filepath, &node, func_name, finding_type, &context.source));
                            }
                        } else {
                            // Check for injection pattern
                            if self.has_injection_pattern(&node, &context.source) {
                                findings.push(self.create_finding(&context.filepath, &node, func_name, finding_type, &context.source));
                            } else {
                                findings.push(self.create_finding(&context.filepath, &node, func_name, finding_type, &context.source));
                            }
                        }
                    }
                }
            }
        }
        
        Ok(findings)
    }

    fn count_total_rules(&self) -> usize {
        let mut count = 0;
        
        if let Some(rules) = &self.rules.injection_sinks { count += rules.len(); }
        if let Some(rules) = &self.rules.crypto_rules { count += rules.len(); }
        if let Some(rules) = &self.rules.path_traversal { count += rules.len(); }
        if let Some(rules) = &self.rules.weak_random { count += rules.len(); }
        if let Some(rules) = &self.rules.hardcoded_secrets { count += rules.len(); }
        if let Some(rules) = &self.rules.malware_detection { count += rules.len(); }
        
        // Add other rule groups
        for rules in self.rules.other.values() {
            count += rules.len();
        }
        
        count
    }

    fn has_injection_pattern(&self, node: &tree_sitter::Node, source: &[u8]) -> bool {
        if let Some(args_node) = self.language_support.get_arguments_node(node) {
            let mut cursor = args_node.walk();
            if cursor.goto_first_child() {
                loop {
                    let arg = cursor.node();
                    let arg_text = get_node_text_slice(&arg, source);
                    if check_for_injection_pattern(arg_text, self.language_support.as_ref()) {
                        return true;
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
        false
    }

    fn create_finding(
        &self,
        file: &str,
        node: &tree_sitter::Node,
        function: &str,
        finding_type: &str,
        source: &[u8],
    ) -> Finding {
        Finding {
            file: file.to_string(),
            line: node.start_position().row + 1,
            function: function.to_string(),
            finding_type: finding_type.to_string(),
            code: get_node_text_slice(node, source).trim().to_string(),
        }
    }

    fn check_ast_conditions(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        conditions: &[Condition],
    ) -> bool {
        conditions.iter().all(|condition| self.check_condition(node, source, condition))
    }

    fn check_condition(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        condition: &Condition,
    ) -> bool {
        match condition.condition_type.as_str() {
            "has_argument" => self.check_has_argument_condition(node, source, condition),
            "in_context" => self.check_in_context_condition(condition),
            "has_parent" => self.check_has_parent_condition(node, condition),
            _ => false,
        }
    }

    fn check_has_argument_condition(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        condition: &Condition,
    ) -> bool {
        if let Some(pattern) = &condition.pattern {
            if let Some(args_node) = self.language_support.get_arguments_node(node) {
                let mut cursor = args_node.walk();
                if cursor.goto_first_child() {
                    loop {
                        let arg = cursor.node();
                        let arg_text = get_node_text_slice(&arg, source);
                        if match_pattern(pattern, arg_text) {
                            return true;
                        }
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
        }
        false
    }

    fn check_in_context_condition(&self, _condition: &Condition) -> bool {
        // Simplified implementation
        if let Some(_context_pattern) = &_condition.pattern {
            // Check if node is in specific context (simplified)
            return true;
        }
        false
    }

    fn check_has_parent_condition(&self, node: &tree_sitter::Node, condition: &Condition) -> bool {
        if let Some(parent_type) = &condition.parent_type {
            if let Some(parent) = node.parent() {
                return parent.kind() == parent_type;
            }
        }
        false
    }
}