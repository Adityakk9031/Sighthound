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
use crate::rules::{Rules, Rule, Condition, match_pattern, rule_matches_pattern, check_for_injection_pattern, is_literal_node, is_in_protective_context};
use super::types::Finding;
use super::pool::{ParserPool, PooledParser};
use super::prefilter::PreFilter;
use super::utils::{rule_applies_to_file};
use super::conditions::{check_ast_conditions};

pub struct VulnerabilityScanner {
    parser: LanguageParser,
    rules: Rules,
    language_name: String,
}

impl VulnerabilityScanner {
    pub fn new(language_name: &str, rules: Rules) -> Result<Self> {
        let parser = LanguageParser::new(language_name)?;
        Ok(Self { 
            parser, 
            rules,
            language_name: language_name.to_string(),
        })
    }

    fn check_ast_conditions(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        conditions: &[Condition],
    ) -> bool {
        check_ast_conditions(node, source, conditions, self.parser.language_support())
    }

    fn has_matching_rules(&self, func_name: &str) -> bool {
        let rule_categories = [
            &self.rules.injection_sinks,
            &self.rules.crypto_rules,
            &self.rules.path_traversal,
            &self.rules.weak_random,
            &self.rules.hardcoded_secrets,
            &self.rules.malware_detection,
        ];

        for category in rule_categories {
            if let Some(rules) = category {
                for rule in rules {
                    if rule_matches_pattern(rule, func_name) {
                        return true;
                    }
                }
            }
        }
        
        // Check other categories
        for rules in self.rules.other.values() {
            for rule in rules {
                if rule_matches_pattern(rule, func_name) {
                    return true;
                }
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
                self.check_rules_category_optimized("malware_detection", &self.rules.malware_detection, &node, source, filepath, func_name, &mut findings);
                
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
                // Check if rule applies to this file first
                if !self.rule_applies_to_file(rule, filepath) {
                    continue;
                }
                
                if rule_matches_pattern(rule, func_name) {
                    let conditions = rule.conditions.as_deref().unwrap_or(&[]);
                    
                    // Enhanced condition checking
                    if self.check_ast_conditions(node, source, conditions) {
                        // Check for sanitization if specified in rule
                        if let Some(sanitizers) = &rule.sanitizers {
                            if self.check_for_sanitization(node, source, sanitizers) {
                                continue; // Skip this finding if sanitized
                            }
                        }
                        
                        let finding_type = rule.finding_type.as_ref().unwrap_or(&category.to_string()).clone();
                        
                        // Enhanced injection sink analysis
                        if category == "injection_sinks" {
                            if self.has_injection_pattern(node, source) {
                                let mut finding = Finding {
                                    file: filepath.to_string(),
                                    line: node.start_position().row + 1,
                                    function: func_name.to_string(),
                                    finding_type: finding_type.clone(),
                                    code: get_node_text(node, source).trim().to_string(),
                                };
                                
                                // Add confidence and severity metadata
                                self.add_finding_metadata(&mut finding, rule, node, source);
                                findings.push(finding);
                            }
                        } else {
                            // For non-injection rules, apply enhanced filtering
                            if self.should_report_finding(node, source, rule) {
                                let mut finding = Finding {
                                    file: filepath.to_string(),
                                    line: node.start_position().row + 1,
                                    function: func_name.to_string(),
                                    finding_type,
                                    code: get_node_text(node, source).trim().to_string(),
                                };
                                
                                self.add_finding_metadata(&mut finding, rule, node, source);
                                findings.push(finding);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check if a rule applies to a specific file based on file_types filters
    fn rule_applies_to_file(&self, rule: &Rule, filepath: &str) -> bool {
        rule_applies_to_file(rule, filepath)
    }

    fn check_for_sanitization(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        sanitizers: &[String],
    ) -> bool {
        // Check if any arguments contain sanitization calls
        if let Some(args_node) = self.parser.language_support().get_arguments_node(node) {
            for i in 0..args_node.named_child_count() {
                if let Some(arg) = args_node.named_child(i) {
                    let arg_text = get_node_text(&arg, source);
                    
                    // Check if argument contains any known sanitization functions
                    for sanitizer in sanitizers {
                        if match_pattern(sanitizer, &arg_text) {
                            return true;
                        }
                    }
                }
            }
        }
        
        // Also check surrounding context for sanitization
        self.check_context_for_sanitization(node, source, sanitizers)
    }

    fn check_context_for_sanitization(
        &self,
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

    fn has_injection_pattern(&self, node: &tree_sitter::Node, source: &[u8]) -> bool {
        if let Some(args_node) = self.parser.language_support().get_arguments_node(node) {
            for i in 0..args_node.named_child_count() {
                if let Some(arg) = args_node.named_child(i) {
                    // Skip if argument is a literal (low risk)
                    if is_literal_node(&arg) {
                        continue;
                    }
                    
                    let arg_text = get_node_text(&arg, source);
                    if check_for_injection_pattern(&arg_text, self.parser.language_support()) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn should_report_finding(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        rule: &Rule,
    ) -> bool {
        // Apply confidence-based filtering
        let confidence = rule.confidence.as_deref().unwrap_or("medium");
        
        match confidence {
            "low" => {
                // For low confidence rules, be more strict
                !is_in_protective_context(node) && !self.has_obvious_guards(node, source)
            }
            "medium" => {
                // For medium confidence, apply moderate filtering
                !self.has_obvious_guards(node, source)
            }
            "high" => {
                // High confidence rules report more freely
                true
            }
            _ => true
        }
    }

    fn has_obvious_guards(&self, node: &tree_sitter::Node, source: &[u8]) -> bool {
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

    fn add_finding_metadata(&self, finding: &mut Finding, rule: &Rule, node: &tree_sitter::Node, _source: &[u8]) {
        // This would extend Finding struct to include metadata
        // For now, we'll append metadata to the finding_type for backward compatibility
        
        let confidence = rule.confidence.as_deref().unwrap_or("medium");
        let _severity = rule.severity.as_deref().unwrap_or("medium");
        
        // Only modify finding_type for low confidence findings to help users prioritize
        if confidence == "low" || (confidence == "medium" && is_in_protective_context(node)) {
            finding.finding_type = format!("{}_low_confidence", finding.finding_type);
        }
    }

    /// Discover files with intelligent pre-filtering
    fn discover_files(&self, root_dir: &str) -> Result<Vec<PathBuf>> {
        let extension = self.parser.file_extension().to_string();
        
        // First, discover all files with target extension
        let all_files: Vec<PathBuf> = WalkDir::new(root_dir)
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

        // Apply intelligent pre-filtering
        let prefilter = PreFilter::new(&self.rules, &self.language_name);
        let (filtered_files, stats) = prefilter.filter_files(all_files);
        
        // Show filtering stats if we filtered anything out
        if stats.filtered_out > 0 {
            let mode = if prefilter.is_malicious_scan() { "malicious" } else { "general" };
            println!("🔍 Scan mode: {} - {}", mode, stats);
        }

        Ok(filtered_files)
    }

    /// Setup progress bars for file discovery and scanning
    fn setup_progress_bars(&self, total_files: usize) -> (ProgressBar, ProgressBar) {
        let multi_progress = MultiProgress::new();
        
        // Discovery progress bar
        let discovery_pb = multi_progress.add(ProgressBar::new_spinner());
        discovery_pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                .template("{spinner:.blue} {msg}")
                .unwrap()
        );
        
        // Scanning progress bar
        let scan_pb = multi_progress.add(ProgressBar::new(total_files as u64));
        scan_pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("#>-")
        );
        
        (discovery_pb, scan_pb)
    }

    pub fn find_vulnerabilities_parallel(&mut self, root_dir: &str, language_name: &str) -> Result<Vec<Finding>> {
        let rules = Arc::new(self.rules.clone());
        
        // Setup and run discovery progress
        let (discovery_pb, scan_pb) = self.setup_progress_bars(0);
        discovery_pb.set_message("Discovering files...");
        discovery_pb.enable_steady_tick(std::time::Duration::from_millis(120));
        
        let files = self.discover_files(root_dir)?;
        let total_files = files.len();
        
        discovery_pb.finish_with_message(format!("📁 Found {} files to scan", total_files));
        
        if total_files == 0 {
            let extension = self.parser.file_extension();
            println!("No files found with extension {}", extension);
            return Ok(Vec::new());
        }

        // Create parser pool - size it to number of threads for optimal performance
        let pool_size = rayon::current_num_threads();
        let parser_pool = ParserPool::new(language_name, pool_size)
            .context("Failed to create parser pool")?;

        println!("🏊 Created parser pool with {} parsers", pool_size);

        // Update scan progress bar with actual file count
        scan_pb.set_length(total_files as u64);
        scan_pb.set_message("Scanning for vulnerabilities...");

        // Setup parallel progress tracking
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

                // Get parser from pool (fast!)
                let mut pooled_parser = PooledParser::new(Arc::clone(&parser_pool))
                    .context("Failed to get parser from pool")?;
                
                let tree = pooled_parser.parser_mut().parse(&source)?;
                
                // Use static method to avoid creating new scanner instances
                let result = Self::scan_file_with_rules(&filepath, &source, &tree, &rules, pooled_parser.parser().language_support());
                
                progress_counter.fetch_add(1, Ordering::Relaxed);
                
                // Parser automatically returned to pool when PooledParser is dropped
                Ok(result)
            })
            .collect();

        progress_handle.join().unwrap();
        
        let all_findings: Vec<Finding> = findings?
            .into_iter()
            .flatten()
            .collect();

        // Print pool statistics
        let stats = parser_pool.stats();
        scan_pb.finish_with_message(format!("✅ Scan complete! Found {} vulnerabilities. {}", all_findings.len(), stats));
        
        Ok(all_findings)
    }

    /// Static method to scan a file without requiring a scanner instance
    fn scan_file_with_rules(
        filepath: &str, 
        source: &[u8], 
        tree: &tree_sitter::Tree, 
        rules: &Rules,
        language_support: &dyn crate::language::LanguageSupport
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let root_node = tree.root_node();
        
        for node in traverse_calls_only(root_node, language_support) {
            if let Some(func_name) = language_support.get_function_name(&node, source) {
                if !Self::has_matching_rules_static(rules, func_name) {
                    continue;
                }
                
                Self::check_rules_category_static("injection_sinks", &rules.injection_sinks, &node, source, filepath, func_name, &mut findings, language_support);
                Self::check_rules_category_static("crypto_rules", &rules.crypto_rules, &node, source, filepath, func_name, &mut findings, language_support);
                Self::check_rules_category_static("path_traversal", &rules.path_traversal, &node, source, filepath, func_name, &mut findings, language_support);
                Self::check_rules_category_static("weak_random", &rules.weak_random, &node, source, filepath, func_name, &mut findings, language_support);
                Self::check_rules_category_static("hardcoded_secrets", &rules.hardcoded_secrets, &node, source, filepath, func_name, &mut findings, language_support);
                Self::check_rules_category_static("malware_detection", &rules.malware_detection, &node, source, filepath, func_name, &mut findings, language_support);
                
                for (category, rules_vec) in &rules.other {
                    Self::check_rules_category_static(category, &Some(rules_vec.clone()), &node, source, filepath, func_name, &mut findings, language_support);
                }
            }
        }

        findings
    }

    /// Static version of has_matching_rules
    fn has_matching_rules_static(rules: &Rules, func_name: &str) -> bool {
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

    /// Static version of check_rules_category_optimized
    fn check_rules_category_static(
        category: &str,
        rules_option: &Option<Vec<Rule>>,
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        func_name: &str,
        findings: &mut Vec<Finding>,
        language_support: &dyn crate::language::LanguageSupport,
    ) {
        if let Some(rules) = rules_option {
            for rule in rules {
                // Check if rule applies to this file first
                if !Self::rule_applies_to_file_static(rule, filepath) {
                    continue;
                }
                
                if rule_matches_pattern(rule, func_name) {
                    let conditions = rule.conditions.as_deref().unwrap_or(&[]);
                    
                    // Enhanced condition checking
                    if Self::check_ast_conditions_static(node, source, conditions, language_support) {
                        // Check for sanitization if specified in rule
                        if let Some(sanitizers) = &rule.sanitizers {
                            if Self::check_for_sanitization_static(node, source, sanitizers) {
                                continue; // Skip this finding if sanitized
                            }
                        }
                        
                        let finding_type = rule.finding_type.as_ref().unwrap_or(&category.to_string()).clone();
                        
                        // Enhanced injection sink analysis
                        if category == "injection_sinks" {
                            if Self::has_injection_pattern_static(node, source) {
                                let mut finding = Finding {
                                    file: filepath.to_string(),
                                    line: node.start_position().row + 1,
                                    function: func_name.to_string(),
                                    finding_type: finding_type.clone(),
                                    code: get_node_text(node, source).trim().to_string(),
                                };
                                
                                // Add confidence and severity metadata
                                Self::add_finding_metadata_static(&mut finding, rule, node);
                                findings.push(finding);
                            }
                        } else {
                            // For non-injection rules, apply enhanced filtering
                            if Self::should_report_finding_static(node, source, rule) {
                                let mut finding = Finding {
                                    file: filepath.to_string(),
                                    line: node.start_position().row + 1,
                                    function: func_name.to_string(),
                                    finding_type,
                                    code: get_node_text(node, source).trim().to_string(),
                                };
                                
                                Self::add_finding_metadata_static(&mut finding, rule, node);
                                findings.push(finding);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Static version of rule_applies_to_file
    fn rule_applies_to_file_static(rule: &Rule, filepath: &str) -> bool {
        rule_applies_to_file(rule, filepath)
    }

    /// Static version of check_ast_conditions
    fn check_ast_conditions_static(
        node: &tree_sitter::Node,
        source: &[u8],
        conditions: &[Condition],
        language_support: &dyn crate::language::LanguageSupport,
    ) -> bool {
        check_ast_conditions(node, source, conditions, language_support)
    }

    /// Static version of check_for_sanitization
    fn check_for_sanitization_static(
        node: &tree_sitter::Node,
        source: &[u8],
        sanitizers: &[String],
    ) -> bool {
        // Simplified check - look for sanitization patterns in the node text
        let node_text = get_node_text(node, source);
        for sanitizer in sanitizers {
            if match_pattern(sanitizer, &node_text) {
                return true;
            }
        }
        false
    }

    /// Static version of has_injection_pattern
    fn has_injection_pattern_static(node: &tree_sitter::Node, source: &[u8]) -> bool {
        // Simplified check - look for common injection patterns
        let node_text = get_node_text(node, source);
        
        // Check for common injection indicators
        let injection_indicators = [
            "%s", "%d", "%f", // Format strings
            "format(", "String.format(", // Format calls
            " + ", // String concatenation
            "${", // Template literals
            ";", "&&", "||", // Command separators
        ];
        
        for indicator in &injection_indicators {
            if node_text.contains(indicator) {
                return true;
            }
        }
        
        false
    }

    /// Static version of should_report_finding
    fn should_report_finding_static(
        node: &tree_sitter::Node,
        source: &[u8],
        rule: &Rule,
    ) -> bool {
        // Apply confidence-based filtering
        let confidence = rule.confidence.as_deref().unwrap_or("medium");
        
        match confidence {
            "low" => {
                // For low confidence rules, be more strict
                !is_in_protective_context(node) && !Self::has_obvious_guards_static(node, source)
            }
            "medium" => {
                // For medium confidence, apply moderate filtering
                !Self::has_obvious_guards_static(node, source)
            }
            "high" => {
                // High confidence rules report more freely
                true
            }
            _ => true
        }
    }

    /// Static version of has_obvious_guards
    fn has_obvious_guards_static(node: &tree_sitter::Node, source: &[u8]) -> bool {
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

    /// Static version of add_finding_metadata
    fn add_finding_metadata_static(finding: &mut Finding, rule: &Rule, node: &tree_sitter::Node) {
        let confidence = rule.confidence.as_deref().unwrap_or("medium");
        
        // Only modify finding_type for low confidence findings to help users prioritize
        if confidence == "low" || (confidence == "medium" && is_in_protective_context(node)) {
            finding.finding_type = format!("{}_low_confidence", finding.finding_type);
        }
    }

    /// Alternative implementation using batched processing for even better performance
    pub fn find_vulnerabilities_batched(&mut self, root_dir: &str, language_name: &str) -> Result<Vec<Finding>> {
        let rules = Arc::new(self.rules.clone());
        let files = self.discover_files(root_dir)?;
        
        if files.is_empty() {
            return Ok(Vec::new());
        }

        // Create parser pool
        let num_threads = rayon::current_num_threads();
        let parser_pool = ParserPool::new(language_name, num_threads)?;
        
        // Calculate optimal batch size
        let batch_size = std::cmp::max(1, files.len() / (num_threads * 2));
        
        println!("🚀 Processing {} files in batches of {} with {} parser pool", 
                files.len(), batch_size, num_threads);

        let findings: Result<Vec<_>, _> = files
            .chunks(batch_size)
            .collect::<Vec<_>>()
            .par_iter()
            .map(|batch| -> Result<Vec<Finding>> {
                let mut batch_findings = Vec::new();
                
                // Get one parser for the entire batch (reduces pool contention)
                let mut pooled_parser = PooledParser::new(Arc::clone(&parser_pool))?;
                
                for file_path in *batch {
                    let filepath = file_path.to_string_lossy().to_string();
                    let source = fs::read(file_path)
                        .context(format!("Failed to read file: {}", filepath))?;
                    
                    let tree = pooled_parser.parser_mut().parse(&source)?;
                    
                    // Use static method to avoid creating new scanner instances
                    let file_findings = Self::scan_file_with_rules(&filepath, &source, &tree, &rules, pooled_parser.parser().language_support());
                    batch_findings.extend(file_findings);
                }
                
                Ok(batch_findings)
            })
            .collect();
            
        let all_findings: Vec<Finding> = findings?.into_iter().flatten().collect();
        
        let stats = parser_pool.stats();
        println!("✅ Batched scan complete! Found {} vulnerabilities. {}", all_findings.len(), stats);
        
        Ok(all_findings)
    }

    pub fn find_vulnerabilities_single_threaded(&mut self, root_dir: &str, _language_name: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Setup and run discovery progress
        let (discovery_pb, scan_pb) = self.setup_progress_bars(0);
        discovery_pb.set_message("Discovering files...");
        discovery_pb.enable_steady_tick(std::time::Duration::from_millis(120));

        let files = self.discover_files(root_dir)?;
        let total_files = files.len();
        
        discovery_pb.finish_with_message(format!("Found {} files to scan", total_files));

        if total_files == 0 {
            let extension = self.parser.file_extension();
            println!("No files found with extension {}", extension);
            return Ok(Vec::new());
        }

        // Update scan progress bar with actual file count
        scan_pb.set_length(total_files as u64);
        scan_pb.set_message("Scanning for vulnerabilities...");

        for (index, file_path) in files.iter().enumerate() {
            let filepath = file_path.to_string_lossy().to_string();
            let source = fs::read(file_path).context(format!("Failed to read file: {}", filepath))?;

            let tree = self.parser.parse(&source)?;
            findings.extend(self.scan_file_optimized(&filepath, &source, &tree));
            
            scan_pb.set_position((index + 1) as u64);
            if index % 10 == 0 || index == total_files - 1 {
                scan_pb.set_message(format!("Scanning: {}", file_path.file_name().unwrap_or_default().to_string_lossy()));
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