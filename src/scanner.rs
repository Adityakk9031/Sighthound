use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use walkdir::WalkDir;

use crate::parser::{LanguageParser, get_node_text, get_function_name, traverse_node};
use crate::rules::{Rules, Rule, Condition, match_pattern};

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub function: String,
    pub finding_type: String,
    pub code: String,
}

pub struct VulnerabilityScanner {
    parser: LanguageParser,
    rules: Rules,
}

impl VulnerabilityScanner {
    pub fn new(language_name: &str, rules: Rules) -> Result<Self> {
        let parser = LanguageParser::new(language_name)?;
        Ok(Self { parser, rules })
    }

    fn check_for_injection_pattern(&self, arg_text: &str) -> bool {
        let patterns = [
            r"%[sdfir]",        // String formatting
            r"\{.*?\}",         // Format strings
            r"\.format\(",      // .format() calls
            r#"['"][^'"]*\s\+\s"#, // String concatenation
            r#"f['""]"#,        // f-strings
            r";",               // Command separators
            r"&&",              // Command chaining
            r"\|\|",            // Command chaining
            r"\$\(",            // Command substitution
            r"`.*?`",           // Backtick execution
        ];

        for pattern in &patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(arg_text) {
                    return true;
                }
            }
        }
        false
    }

    fn check_ast_conditions(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        conditions: &[Condition],
    ) -> bool {
        if conditions.is_empty() {
            return true;
        }

        for condition in conditions {
            match condition.condition_type.as_str() {
                "has_argument" => {
                    if let Some(pattern) = &condition.pattern {
                        if let Some(args_node) = node.child_by_field_name("arguments") {
                            let mut found_match = false;
                            for i in 0..args_node.named_child_count() {
                                if let Some(arg) = args_node.named_child(i) {
                                    let arg_text = get_node_text(&arg, source);
                                    if match_pattern(pattern, &arg_text) {
                                        found_match = true;
                                        break;
                                    }
                                }
                            }
                            if !found_match {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                }
                "in_context" => {
                    if let Some(not_in) = &condition.not_in {
                        if let Some(parent) = node.parent() {
                            if not_in.contains(&"comment".to_string()) && parent.kind() == "comment" {
                                return false;
                            }
                        }
                    }
                }
                "has_parent" => {
                    if let Some(parent_type) = &condition.parent_type {
                        if let Some(parent) = node.parent() {
                            if parent.kind() != parent_type {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                }
                _ => {} // Unknown condition type, ignore
            }
        }
        true
    }

    fn scan_file(&self, filepath: &str, source: &[u8], tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let root_node = tree.root_node();
        let nodes = traverse_node(root_node);

        for node in nodes {
            if node.kind() == "call" {
                if let Some(func_name) = get_function_name(&node, source) {
                    // Check all rule categories
                    self.check_rules_category("injection_sinks", &self.rules.injection_sinks, &node, source, filepath, &func_name, &mut findings);
                    self.check_rules_category("crypto_rules", &self.rules.crypto_rules, &node, source, filepath, &func_name, &mut findings);
                    self.check_rules_category("path_traversal", &self.rules.path_traversal, &node, source, filepath, &func_name, &mut findings);
                    self.check_rules_category("weak_random", &self.rules.weak_random, &node, source, filepath, &func_name, &mut findings);
                    self.check_rules_category("hardcoded_secrets", &self.rules.hardcoded_secrets, &node, source, filepath, &func_name, &mut findings);
                    
                    // Check other rule categories
                    for (category, rules) in &self.rules.other {
                        self.check_rules_category(category, &Some(rules.clone()), &node, source, filepath, &func_name, &mut findings);
                    }
                }
            }
        }

        findings
    }

    fn check_rules_category(
        &self,
        category: &str,
        rules_option: &Option<Vec<Rule>>,
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        func_name: &str,
        findings: &mut Vec<Finding>,
    ) {
        if let Some(rules) = rules_option {
            for rule in rules {
                if match_pattern(&rule.pattern, func_name) {
                    let conditions = rule.conditions.as_deref().unwrap_or(&[]);
                    if self.check_ast_conditions(node, source, conditions) {
                        let finding_type = rule.finding_type.as_ref().unwrap_or(&category.to_string()).clone();
                        
                        if category == "injection_sinks" {
                            // Check arguments for injection patterns
                            if let Some(args_node) = node.child_by_field_name("arguments") {
                                for i in 0..args_node.named_child_count() {
                                    if let Some(arg) = args_node.named_child(i) {
                                        let arg_text = get_node_text(&arg, source);
                                        if self.check_for_injection_pattern(&arg_text) {
                                            findings.push(Finding {
                                                file: filepath.to_string(),
                                                line: node.start_position().row + 1,
                                                function: func_name.to_string(),
                                                finding_type: finding_type.clone(),
                                                code: get_node_text(node, source).trim().to_string(),
                                            });
                                            break;
                                        }
                                    }
                                }
                            }
                        } else {
                            // For other rules, just add the finding
                            findings.push(Finding {
                                file: filepath.to_string(),
                                line: node.start_position().row + 1,
                                function: func_name.to_string(),
                                finding_type,
                                code: get_node_text(node, source).trim().to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    pub fn find_vulnerabilities(&mut self, root_dir: &str, language_name: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let extension = self.parser.get_file_extension(language_name).to_string();

        for entry in WalkDir::new(root_dir) {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| {
                format!(".{}", ext.to_string_lossy()) == extension
            }) {
                let filepath = path.to_string_lossy().to_string();
                let source = fs::read(path).context(format!("Failed to read file: {}", filepath))?;

                let tree = self.parser.parse(&source)?;
                findings.extend(self.scan_file(&filepath, &source, &tree));
            }
        }

        Ok(findings)
    }
}

pub fn print_summary(findings: &[Finding]) {
    println!("\nVulnerability Summary -----------------");

    // Count findings by type
    let mut finding_types: HashMap<String, usize> = HashMap::new();
    for finding in findings {
        *finding_types.entry(finding.finding_type.clone()).or_insert(0) += 1;
    }

    // Print summary by finding type
    let mut sorted_types: Vec<_> = finding_types.iter().collect();
    sorted_types.sort_by_key(|&(k, _)| k);
    for (finding_type, count) in sorted_types {
        println!("{}: {} occurrences", finding_type, count);
    }

    // Print files with most vulnerabilities
    let mut file_counts: HashMap<String, usize> = HashMap::new();
    for finding in findings {
        *file_counts.entry(finding.file.clone()).or_insert(0) += 1;
    }

    println!("\nMost vulnerable files:");
    let mut sorted_files: Vec<_> = file_counts.iter().collect();
    sorted_files.sort_by(|a, b| b.1.cmp(a.1));
    for (file_path, count) in sorted_files.iter().take(5) {
        println!("{}: {} vulnerabilities", file_path, count);
    }

    println!("\nTotal vulnerabilities found: {}", findings.len());
} 