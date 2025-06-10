use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};

use crate::parser::LanguageParser;
use crate::rules::Rules;
use super::types::Finding;
use super::shared::ScanningLogic;

pub struct VulnerabilityScanner {
    parser: LanguageParser,
    rules: Rules,
}

impl VulnerabilityScanner {
    pub fn new(language_name: &str, rules: Rules) -> Result<Self> {
        let parser = LanguageParser::new(language_name)?;
        Ok(Self { 
            parser, 
            rules,
        })
    }

    fn scan_file_optimized(&self, filepath: &str, source: &[u8], tree: &tree_sitter::Tree) -> Vec<Finding> {
        // Use shared scanning logic
        let all_rules = ScanningLogic::get_all_rules(&self.rules);
        ScanningLogic::scan_file_with_rules(
            filepath,
            source,
            tree,
            &all_rules,
            self.parser.language_support(),
        )
    }

    fn discover_files(&self, root_dir: &str) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        let target_extension = self.parser.file_extension();
        
        for entry in WalkDir::new(root_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if let Some(ext_str) = extension.to_str() {
                        let file_ext = format!(".{}", ext_str);
                        if file_ext == target_extension {
                            files.push(path.to_path_buf());
                        }
                    }
                }
            }
        }
        
        Ok(files)
    }

    fn setup_progress_bars(&self, total_files: usize) -> (ProgressBar, ProgressBar) {
        let multi_progress = MultiProgress::new();
        
        let file_progress = multi_progress.add(ProgressBar::new(total_files as u64));
        file_progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
                .unwrap()
                .progress_chars("#>-")
        );
        file_progress.set_message("Scanning files");
        
        let finding_progress = multi_progress.add(ProgressBar::new(0));
        finding_progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.yellow} Found {pos} vulnerabilities")
                .unwrap()
        );
        
        (file_progress, finding_progress)
    }

    pub fn find_vulnerabilities_parallel(&mut self, root_dir: &str, language_name: &str) -> Result<Vec<Finding>> {
        let files = self.discover_files(root_dir)?;
        
        if files.is_empty() {
            println!("No {} files found in {}", language_name, root_dir);
            return Ok(Vec::new());
        }

        let (file_progress, finding_progress) = self.setup_progress_bars(files.len());
        let total_findings = Arc::new(AtomicUsize::new(0));
        
        let scanner_rules = Arc::new(self.rules.clone());
        
        let findings: Vec<Finding> = files
            .par_iter()
            .filter_map(|file_path| {
                let filepath = file_path.to_string_lossy().to_string();
                
                match fs::read(&filepath) {
                    Ok(source) => {
                        // Create a temporary scanner for this thread
                        match VulnerabilityScanner::new(language_name, (*scanner_rules).clone()) {
                            Ok(mut scanner) => {
                                match scanner.parser.parse(&source) {
                                    Ok(tree) => {
                                        let file_findings = scanner.scan_file_optimized(&filepath, &source, &tree);
                                        
                                        let finding_count = file_findings.len();
                                        if finding_count > 0 {
                                            total_findings.fetch_add(finding_count, Ordering::Relaxed);
                                            finding_progress.set_position(total_findings.load(Ordering::Relaxed) as u64);
                                        }
                                        
                                        file_progress.inc(1);
                                        Some(file_findings)
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to parse {}: {}", filepath, e);
                                        file_progress.inc(1);
                                        None
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to create scanner: {}", e);
                                file_progress.inc(1);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to read file {}: {}", filepath, e);
                        file_progress.inc(1);
                        None
                    }
                }
            })
            .flatten()
            .collect();
        
        file_progress.finish_with_message("Scan complete");
        finding_progress.finish_with_message("Scan complete");
        
        Ok(findings)
    }

    pub fn find_vulnerabilities_batched(&mut self, root_dir: &str, language_name: &str) -> Result<Vec<Finding>> {
        let files = self.discover_files(root_dir)?;
        
        if files.is_empty() {
            println!("No {} files found in {}", language_name, root_dir);
            return Ok(Vec::new());
        }

        let (file_progress, finding_progress) = self.setup_progress_bars(files.len());
        let total_findings = Arc::new(AtomicUsize::new(0));
        
        let scanner_rules = Arc::new(self.rules.clone());
        
        let chunk_size = 10;
        let findings: Vec<Finding> = files
            .chunks(chunk_size)
            .par_bridge()
            .map(|chunk| {
                let mut chunk_findings = Vec::new();
                
                // Create one scanner per chunk
                if let Ok(mut scanner) = VulnerabilityScanner::new(language_name, (*scanner_rules).clone()) {
                    for file_path in chunk {
                        let filepath = file_path.to_string_lossy().to_string();
                        
                        match fs::read(&filepath) {
                            Ok(source) => {
                                match scanner.parser.parse(&source) {
                                    Ok(tree) => {
                                        let file_findings = scanner.scan_file_optimized(&filepath, &source, &tree);
                                        chunk_findings.extend(file_findings);
                                    }
                                    Err(e) => eprintln!("Failed to parse {}: {}", filepath, e),
                                }
                            }
                            Err(e) => eprintln!("Failed to read file {}: {}", filepath, e),
                        }
                        
                        file_progress.inc(1);
                    }
                }
                
                let chunk_count = chunk_findings.len();
                if chunk_count > 0 {
                    total_findings.fetch_add(chunk_count, Ordering::Relaxed);
                    finding_progress.set_position(total_findings.load(Ordering::Relaxed) as u64);
                }
                
                chunk_findings
            })
            .flatten()
            .collect();
        
        file_progress.finish_with_message("Scan complete");
        finding_progress.finish_with_message("Scan complete");
        
        Ok(findings)
    }

    pub fn find_vulnerabilities_single_threaded(&mut self, root_dir: &str, _language_name: &str) -> Result<Vec<Finding>> {
        let files = self.discover_files(root_dir)?;
        let mut all_findings = Vec::new();
        
        for file_path in files {
            let filepath = file_path.to_string_lossy().to_string();
            
            match fs::read(&filepath) {
                Ok(source) => {
                    match self.parser.parse(&source) {
                        Ok(tree) => {
                            let findings = self.scan_file_optimized(&filepath, &source, &tree);
                            all_findings.extend(findings);
                        }
                        Err(e) => eprintln!("Failed to parse {}: {}", filepath, e),
                    }
                }
                Err(e) => eprintln!("Failed to read file {}: {}", filepath, e),
            }
        }
        
        Ok(all_findings)
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