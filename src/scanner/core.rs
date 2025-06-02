use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};

use crate::parser::{LanguageParser, get_node_text, traverse_calls_only};
use crate::rules::{Rules, Rule, Condition, match_pattern, check_for_injection_pattern};
use super::types::Finding;

pub struct VulnerabilityScanner {
    parser: LanguageParser,
    rules: Rules,
}

impl VulnerabilityScanner {
    pub fn new(language_name: &str, rules: Rules) -> Result<Self> {
        let parser = LanguageParser::new(language_name)?;
        Ok(Self { parser, rules })
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
                        if let Some(args_node) = self.parser.language_support().get_arguments_node(node) {
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
                _ => {}
            }
        }
        true
    }

    fn has_matching_rules(&self, func_name: &str) -> bool {
        let rule_categories = [
            &self.rules.injection_sinks,
            &self.rules.crypto_rules,
            &self.rules.path_traversal,
            &self.rules.weak_random,
            &self.rules.hardcoded_secrets,
        ];

        for category in &rule_categories {
            if let Some(rules) = category {
                if rules.iter().any(|rule| match_pattern(&rule.pattern, func_name)) {
                    return true;
                }
            }
        }

        for rules in self.rules.other.values() {
            if rules.iter().any(|rule| match_pattern(&rule.pattern, func_name)) {
                return true;
            }
        }

        false
    }

    fn scan_file_optimized(&self, filepath: &str, source: &[u8], tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let root_node = tree.root_node();
        let language_support = self.parser.language_support();
        
        for node in traverse_calls_only(root_node, language_support) {
            if let Some(func_name) = language_support.get_function_name(&node, source) {
                if !self.has_matching_rules(func_name) {
                    continue;
                }
                
                self.check_rules_category_optimized("injection_sinks", &self.rules.injection_sinks, &node, source, filepath, func_name, &mut findings);
                self.check_rules_category_optimized("crypto_rules", &self.rules.crypto_rules, &node, source, filepath, func_name, &mut findings);
                self.check_rules_category_optimized("path_traversal", &self.rules.path_traversal, &node, source, filepath, func_name, &mut findings);
                self.check_rules_category_optimized("weak_random", &self.rules.weak_random, &node, source, filepath, func_name, &mut findings);
                self.check_rules_category_optimized("hardcoded_secrets", &self.rules.hardcoded_secrets, &node, source, filepath, func_name, &mut findings);
                
                for (category, rules) in &self.rules.other {
                    self.check_rules_category_optimized(category, &Some(rules.clone()), &node, source, filepath, func_name, &mut findings);
                }
            }
        }

        findings
    }

    fn check_rules_category_optimized(
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
                            if let Some(args_node) = self.parser.language_support().get_arguments_node(node) {
                                for i in 0..args_node.named_child_count() {
                                    if let Some(arg) = args_node.named_child(i) {
                                        let arg_text = get_node_text(&arg, source);
                                        if check_for_injection_pattern(&arg_text, self.parser.language_support()) {
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

    pub fn find_vulnerabilities_parallel(&mut self, root_dir: &str, language_name: &str) -> Result<Vec<Finding>> {
        let extension = self.parser.file_extension().to_string();
        let rules = Arc::new(self.rules.clone());
        
        let multi_progress = MultiProgress::new();
        let main_pb = multi_progress.add(ProgressBar::new_spinner());
        main_pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                .template("{spinner:.blue} {msg}")
                .unwrap()
        );
        main_pb.set_message("Discovering files...");
        main_pb.enable_steady_tick(std::time::Duration::from_millis(120));
        
        let files: Vec<PathBuf> = WalkDir::new(root_dir)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry.path().is_file() && 
                entry.path().extension().map_or(false, |ext| {
                    format!(".{}", ext.to_string_lossy()) == extension
                })
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();

        let total_files = files.len();
        main_pb.finish_with_message(format!("📁 Found {} files to scan", total_files));
        
        if total_files == 0 {
            println!("No files found with extension {}", extension);
            return Ok(Vec::new());
        }

        let scan_pb = multi_progress.add(ProgressBar::new(total_files as u64));
        scan_pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("#>-")
        );
        scan_pb.set_message("Scanning for vulnerabilities...");

        let progress_counter = Arc::new(AtomicUsize::new(0));
        let progress_counter_clone = Arc::clone(&progress_counter);
        let scan_pb_clone = scan_pb.clone();

        let progress_handle = std::thread::spawn(move || {
            while progress_counter_clone.load(Ordering::Relaxed) < total_files {
                let current = progress_counter_clone.load(Ordering::Relaxed);
                scan_pb_clone.set_position(current as u64);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            scan_pb_clone.set_position(total_files as u64);
        });

        let findings: Result<Vec<Vec<Finding>>, anyhow::Error> = files
            .par_iter()
            .map(|file_path| -> Result<Vec<Finding>> {
                let filepath = file_path.to_string_lossy().to_string();
                let source = fs::read(file_path)
                    .context(format!("Failed to read file: {}", filepath))?;

                let mut parser = LanguageParser::new(language_name)?;
                let tree = parser.parse(&source)?;
                
                let scanner = VulnerabilityScanner::new(language_name, (*rules).clone())?;
                let result = scanner.scan_file_optimized(&filepath, &source, &tree);
                
                progress_counter.fetch_add(1, Ordering::Relaxed);
                
                Ok(result)
            })
            .collect();

        progress_handle.join().unwrap();
        
        let all_findings: Vec<Finding> = findings?
            .into_iter()
            .flatten()
            .collect();

        scan_pb.finish_with_message(format!("✅ Scan complete! Found {} vulnerabilities", all_findings.len()));
        
        Ok(all_findings)
    }

    pub fn find_vulnerabilities_single_threaded(&mut self, root_dir: &str, _language_name: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let extension = self.parser.file_extension().to_string();

        let multi_progress = MultiProgress::new();
        let main_pb = multi_progress.add(ProgressBar::new_spinner());
        main_pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                .template("{spinner:.blue} {msg}")
                .unwrap()
        );
        main_pb.set_message("Discovering files...");
        main_pb.enable_steady_tick(std::time::Duration::from_millis(120));

        let files: Vec<_> = WalkDir::new(root_dir)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry.path().is_file() && 
                entry.path().extension().map_or(false, |ext| {
                    format!(".{}", ext.to_string_lossy()) == extension
                })
            })
            .collect();

        let total_files = files.len();
        main_pb.finish_with_message(format!("Found {} files to scan", total_files));

        if total_files == 0 {
            println!("No files found with extension {}", extension);
            return Ok(Vec::new());
        }

        let scan_pb = multi_progress.add(ProgressBar::new(total_files as u64));
        scan_pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("#>-")
        );
        scan_pb.set_message("Scanning for vulnerabilities...");

        for (index, entry) in files.iter().enumerate() {
            let path = entry.path();
            let filepath = path.to_string_lossy().to_string();
            let source = fs::read(path).context(format!("Failed to read file: {}", filepath))?;

            let tree = self.parser.parse(&source)?;
            findings.extend(self.scan_file_optimized(&filepath, &source, &tree));
            
            scan_pb.set_position((index + 1) as u64);
            if index % 10 == 0 || index == total_files - 1 {
                scan_pb.set_message(format!("Scanning: {}", path.file_name().unwrap_or_default().to_string_lossy()));
            }
        }

        scan_pb.finish_with_message(format!("✅ Scan complete! Found {} vulnerabilities", findings.len()));

        Ok(findings)
    }
}

pub fn print_summary(findings: &[Finding]) {
    println!("\nVulnerability Summary -----------------");

    let mut finding_types: HashMap<String, usize> = HashMap::new();
    for finding in findings {
        *finding_types.entry(finding.finding_type.clone()).or_insert(0) += 1;
    }

    let mut sorted_types: Vec<_> = finding_types.iter().collect();
    sorted_types.sort_by_key(|&(k, _)| k);
    for (finding_type, count) in sorted_types {
        println!("{}: {} occurrences", finding_type, count);
    }

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