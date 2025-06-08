use anyhow::Result;
use std::path::Path;
use crate::language::LanguageSupport;
use crate::rules::{Rule, Rules, Condition, rule_matches_pattern};
use crate::{traverse_calls_only, get_node_text_slice, check_for_injection_pattern};
use super::types::{Finding, ScanContext, FilteringStats};
use super::utils::{rule_applies_to_file_path};
use super::conditions::{check_ast_conditions};

pub struct FileTypeAwareAnalyzer {
    language_support: Box<dyn LanguageSupport>,
    rules: Rules,
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
        let _extension = file_path.extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        // NOTE: Disabled caching for now since include/exclude patterns depend on full file path
        // TODO: Implement more sophisticated caching that considers path patterns
        // Check cache first
        // if let Some(cached_rules) = self.rules_by_extension.get(&extension) {
        //     self.stats.cache_hits += 1;
        //     return cached_rules.clone();
        // }

        // Collect all rules
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

        // NOTE: Disabled caching for now since include/exclude patterns depend on full file path
        // Cache the result
        // self.rules_by_extension.insert(extension, applicable_rules.clone());
        applicable_rules
    }

    fn rule_applies_to_file(&self, rule: &Rule, file_path: &Path) -> bool {
        rule_applies_to_file_path(rule, file_path)
    }

    fn scan_with_rules(&mut self, context: &ScanContext, rules: Vec<Rule>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let root_node = context.tree.root_node();
        
        for node in traverse_calls_only(root_node, self.language_support.as_ref()) {
            if let Some(func_name) = self.language_support.get_function_name(&node, &context.source) {
                for rule in &rules {
                    if rule_matches_pattern(rule, func_name) {
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
        check_ast_conditions(node, source, conditions, self.language_support.as_ref())
    }
}