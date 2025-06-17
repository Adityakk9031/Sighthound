use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;
use indicatif::{ProgressBar, ProgressStyle};
use std::cell::RefCell;
use crate::parser::LanguageParser;
use memmap2::Mmap;
use std::fs::File;
use std::time::Duration;

use crate::rules::Rules;
use super::types::Finding;
use super::shared::ScanningLogic;

thread_local! {
    // Store (language_name, parser) so we can reuse per language inside each thread
    static TLS_PARSER: RefCell<Option<(String, LanguageParser)>> = RefCell::new(None);
}

fn with_local_parser<F, R>(language: &str, f: F) -> Result<R>
where
    F: FnOnce(&mut LanguageParser) -> Result<R>,
{
    TLS_PARSER.try_with(|cell| {
        let mut opt = cell.borrow_mut();
        match *opt {
            Some((ref lang, ref mut parser)) if lang == language => f(parser),
            _ => {
                let mut parser = LanguageParser::new(language)?;
                let result = f(&mut parser)?;
                *opt = Some((language.to_string(), parser));
                Ok(result)
            }
        }
    })?
}

pub struct VulnerabilityScanner {
    language: String,
    rules: Rules,
}

impl VulnerabilityScanner {
    pub fn new(language_name: &str, rules: Rules) -> Result<Self> {
        Ok(Self { 
            language: language_name.to_string(),
            rules,
        })
    }

    fn discover_files(&self, root_dir: &str) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        // Get extension once using a fresh parser (cheap, happens only once)
        let parser = LanguageParser::new(&self.language)?;
        let target_extension = parser.file_extension();
        
        // Common environment directories to skip
        let skip_dirs = [
            "venv", "env", ".venv", ".env",
            "node_modules", ".git",
            "__pycache__", ".pytest_cache",
            "target", "build", "dist",
            ".idea", ".vscode",
        ];

        for entry in WalkDir::new(root_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if skip_dirs.contains(&name) {
                        continue;
                    }
                }
                continue;
            }
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if format!(".{}", ext) == target_extension {
                        files.push(path.to_path_buf());
                    }
                }
            }
        }
        Ok(files)
    }

    fn setup_progress_bars(&self, total_files: usize) -> ProgressBar {
        let bar = ProgressBar::new(total_files as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
                .unwrap()
                .progress_chars("#>-")
        );
        bar.set_message("Scanning files");
        bar
    }

    pub fn find_vulnerabilities_parallel(&self, root_dir: &str, language_name: &str, show_progress: bool) -> Result<Vec<Finding>> {
        let files = self.discover_files(root_dir)?;
        if files.is_empty() {
            println!("No {} files found in {}", language_name, root_dir);
            return Ok(Vec::new());
        }

        let file_progress = if show_progress { Some(self.setup_progress_bars(files.len())) } else { None };
        let total_findings = Arc::new(AtomicUsize::new(0));
        let all_rules = ScanningLogic::get_all_rules(&self.rules);
        let chunk_size = 64; // tuned for slower disks

        use rayon::slice::ParallelSlice;

        let processed = Arc::new(AtomicUsize::new(0));
        let progress_handle = if let Some(ref bar) = file_progress {
            let bar_clone = bar.clone();
            Some({
                let processed = Arc::clone(&processed);
                std::thread::spawn(move || {
                    loop {
                        let val = processed.load(Ordering::Relaxed) as u64;
                        bar_clone.set_position(val);
                        if val >= bar_clone.length().unwrap_or(0) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                })
            })
        } else { None };

        let findings: Vec<Finding> = files
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                let mut local_vec = Vec::new();
                for path in chunk {
                    let filepath_str = path.to_string_lossy().to_string();
                    match File::open(&path) {
                        Ok(file) => {
                            match unsafe { Mmap::map(&file) } {
                                Ok(mmap) => {
                                    let source: &[u8] = &mmap;
                                    match with_local_parser(&self.language, |parser| {
                                        let tree = parser.parse(source)?;
                                        Ok(ScanningLogic::scan_file_with_rules(
                                            &filepath_str,
                                            source,
                                            &tree,
                                            &all_rules,
                                            parser.language_support(),
                                        ))
                                    }) {
                                        Ok(file_findings) => {
                                            if !file_findings.is_empty() {
                                                total_findings.fetch_add(file_findings.len(), Ordering::Relaxed);
                                            }
                                            local_vec.extend(file_findings);
                                        }
                                        Err(e) => eprintln!("Failed to parse {}: {}", filepath_str, e),
                                    }
                                }
                                Err(e) => eprintln!("Failed to mmap file {}: {}", filepath_str, e),
                            }
                        }
                        Err(err) => eprintln!("Failed to open file {}: {}", filepath_str, err),
                    }
                }
                processed.fetch_add(chunk.len(), Ordering::Relaxed);
                local_vec
            })
            .collect();

        if let Some(handle) = progress_handle { let _ = handle.join(); }
        if let Some(bar) = file_progress { bar.finish_with_message("Scan complete"); }
        println!("Found {} vulnerabilities", total_findings.load(Ordering::Relaxed));
        Ok(findings)
    }

    pub fn find_vulnerabilities_single_threaded(&self, root_dir: &str, _language_name: &str) -> Result<Vec<Finding>> {
        let files = self.discover_files(root_dir)?;
        if files.is_empty() { return Ok(Vec::new()); }
        let mut all_findings = Vec::new();
        let all_rules = ScanningLogic::get_all_rules(&self.rules);

        for path in files {
            let filepath = path.to_string_lossy().to_string();
            if let Ok(source) = fs::read(&filepath) {
                match with_local_parser(&self.language, |parser| {
                    let tree = parser.parse(&source)?;
                    Ok(ScanningLogic::scan_file_with_rules(
                        &filepath,
                        &source,
                        &tree,
                        &all_rules,
                        parser.language_support(),
                    ))
                }) {
                    Ok(fnds) => all_findings.extend(fnds),
                    Err(e) => eprintln!("Failed to parse {}: {}", filepath, e),
                }
            }
        }
        Ok(all_findings)
    }
}

pub fn print_summary(findings: &[Finding], duration: std::time::Duration) {
    println!("\n\x1b[1;36m=== Vulnerability Summary ===\x1b[0m");

    // Group findings by severity
    let mut severity_counts: HashMap<String, usize> = HashMap::new();
    let mut finding_types: HashMap<String, usize> = HashMap::new();
    let mut file_counts: HashMap<String, usize> = HashMap::new();

    for finding in findings {
        *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
        *finding_types.entry(finding.finding_type.clone()).or_insert(0) += 1;
        *file_counts.entry(finding.file.clone()).or_insert(0) += 1;
    }

    // Print severity breakdown
    println!("\n\x1b[1;33mSeverity Breakdown:\x1b[0m");
    let severity_order = ["critical", "high", "medium", "low"];
    for severity in severity_order {
        if let Some(count) = severity_counts.get(severity) {
            let color = match severity {
                "critical" => "\x1b[31;1m", // Bright red
                "high" => "\x1b[31m",      // Red
                "medium" => "\x1b[33m",    // Yellow
                "low" => "\x1b[32m",       // Green
                _ => "\x1b[0m",
            };
            println!("  {}{}\x1b[0m {} findings", 
                    color, 
                    "●",
                    count);
        }
    }

    // Print finding types
    println!("\n\x1b[1;33mFinding Types:\x1b[0m");
    let mut sorted_types: Vec<_> = finding_types.iter().collect();
    sorted_types.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count descending
    for (finding_type, count) in sorted_types {
        println!("  \x1b[36m●\x1b[0m {}: {} occurrences", finding_type, count);
    }

    // Print most vulnerable files
    println!("\n\x1b[1;33mMost Vulnerable Files:\x1b[0m");
    let mut sorted_files: Vec<_> = file_counts.iter().collect();
    sorted_files.sort_by(|a, b| b.1.cmp(a.1));
    for (file_path, count) in sorted_files.iter().take(5) {
        println!("  \x1b[34m●\x1b[0m {}: {} vulnerabilities", file_path, count);
    }

    // Print total
    println!("\n\x1b[1;36mTotal Findings: \x1b[1;33m{}\x1b[0m", findings.len());
    println!("\x1b[1;36mScan Time: \x1b[1;33m{:.2?}\x1b[0m", duration);
}