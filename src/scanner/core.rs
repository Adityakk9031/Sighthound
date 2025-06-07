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
use crate::rules::{Rules, Rule, Condition, match_pattern, match_any_pattern, check_for_injection_pattern, is_literal_node, is_in_protective_context};
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
            if !self.check_single_condition(node, source, condition) {
                return false;
            }
        }
        true
    }

    fn check_single_condition(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        condition: &Condition,
    ) -> bool {
        match condition.condition_type.as_str() {
            "has_argument" => {
                self.check_has_argument_condition(node, source, condition)
            }
            "in_context" => {
                self.check_in_context_condition(node, condition)
            }
            "has_parent" => {
                self.check_has_parent_condition(node, condition)
            }
            "not_literal" => {
                self.check_not_literal_condition(node, source, condition)
            }
            "not_in_protective_context" => {
                !is_in_protective_context(node)
            }
            "has_ancestor" => {
                self.check_has_ancestor_condition(node, condition)
            }
            "argument_not_sanitized" => {
                self.check_argument_not_sanitized_condition(node, source, condition)
            }
            "has_sibling_pattern" => {
                self.check_has_sibling_pattern_condition(node, source, condition)
            }
            _ => {
                // Unknown condition type, default to false for safety
                false
            }
        }
    }

    fn check_has_argument_condition(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        condition: &Condition,
    ) -> bool {
        if let Some(args_node) = self.parser.language_support().get_arguments_node(node) {
            // If specific position is specified, check only that argument
            if let Some(position) = condition.argument_position {
                if let Some(arg) = args_node.named_child(position) {
                    return self.check_argument_matches(arg, source, condition);
                }
                return false;
            }
            
            // Otherwise check all arguments
            for i in 0..args_node.named_child_count() {
                if let Some(arg) = args_node.named_child(i) {
                    if self.check_argument_matches(arg, source, condition) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn check_argument_matches(
        &self,
        arg: tree_sitter::Node,
        source: &[u8],
        condition: &Condition,
    ) -> bool {
        let arg_text = get_node_text(&arg, source);
        
        // Check node type if specified
        if let Some(expected_type) = &condition.node_type {
            if arg.kind() != expected_type {
                return false;
            }
        }
        
        // Check pattern(s)
        if let Some(pattern) = &condition.pattern {
            return match_pattern(pattern, &arg_text);
        }
        
        if let Some(patterns) = &condition.patterns {
            return match_any_pattern(patterns, &arg_text);
        }
        
        true
    }

    fn check_in_context_condition(
        &self,
        node: &tree_sitter::Node,
        _condition: &Condition,
    ) -> bool {
        if let Some(not_in) = &_condition.not_in {
            if let Some(parent) = node.parent() {
                if not_in.contains(&"comment".to_string()) && parent.kind() == "comment" {
                    return false;
                }
                if not_in.contains(&"string".to_string()) && parent.kind() == "string" {
                    return false;
                }
            }
        }
        true
    }

    fn check_has_parent_condition(
        &self,
        node: &tree_sitter::Node,
        condition: &Condition,
    ) -> bool {
        if let Some(parent_type) = &condition.parent_type {
            if let Some(parent) = node.parent() {
                return parent.kind() == parent_type;
            }
            return false;
        }
        true
    }

    fn check_not_literal_condition(
        &self,
        node: &tree_sitter::Node,
        _source: &[u8],
        condition: &Condition,
    ) -> bool {
        if let Some(args_node) = self.parser.language_support().get_arguments_node(node) {
            if let Some(position) = condition.argument_position {
                if let Some(arg) = args_node.named_child(position) {
                    return !is_literal_node(&arg);
                }
            } else {
                // Check if any argument is not literal
                for i in 0..args_node.named_child_count() {
                    if let Some(arg) = args_node.named_child(i) {
                        if !is_literal_node(&arg) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn check_has_ancestor_condition(
        &self,
        node: &tree_sitter::Node,
        condition: &Condition,
    ) -> bool {
        if let Some(ancestor_types) = &condition.ancestor_types {
            let mut current = node.parent();
            let mut depth = 0;
            
            while let Some(parent) = current {
                if depth > 20 {  // Limit search depth
                    break;
                }
                
                if ancestor_types.contains(&parent.kind().to_string()) {
                    return true;
                }
                
                current = parent.parent();
                depth += 1;
            }
        }
        false
    }

    fn check_argument_not_sanitized_condition(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        condition: &Condition,
    ) -> bool {
        if let Some(sanitizer_patterns) = &condition.patterns {
            if let Some(args_node) = self.parser.language_support().get_arguments_node(node) {
                for i in 0..args_node.named_child_count() {
                    if let Some(arg) = args_node.named_child(i) {
                        let arg_text = get_node_text(&arg, source);
                        
                        // Check if argument contains any sanitization patterns
                        for sanitizer in sanitizer_patterns {
                            if match_pattern(sanitizer, &arg_text) {
                                return false;  // Found sanitization, so condition fails
                            }
                        }
                    }
                }
            }
            return true;  // No sanitization found
        }
        true
    }

    fn check_has_sibling_pattern_condition(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        condition: &Condition,
    ) -> bool {
        if let Some(patterns) = &condition.patterns {
            if let Some(parent) = node.parent() {
                let mut cursor = parent.walk();
                if cursor.goto_first_child() {
                    loop {
                        let sibling = cursor.node();
                        if sibling != *node {
                            let sibling_text = get_node_text(&sibling, source);
                            if match_any_pattern(patterns, &sibling_text) {
                                return true;
                            }
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

    fn has_matching_rules(&self, func_name: &str) -> bool {
        let rule_categories = [
            &self.rules.injection_sinks,
            &self.rules.crypto_rules,
            &self.rules.path_traversal,
            &self.rules.weak_random,
            &self.rules.hardcoded_secrets,
            &self.rules.malware_detection,
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
                if match_pattern(&rule.pattern, func_name) {
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

    /// Discover files with the scanner's target extension in the given directory
    fn discover_files(&self, root_dir: &str) -> Result<Vec<PathBuf>> {
        let extension = self.parser.file_extension().to_string();
        
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

        Ok(files)
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