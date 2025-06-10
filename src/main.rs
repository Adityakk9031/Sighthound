use anyhow::Result;
use clap::Parser;
use find_vulns::{Cli, Rules, VulnerabilityScanner, print_summary, Finding};
use find_vulns::scanner::ScanningLogic;
use find_vulns::parser::LanguageParser;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};

fn detect_language_from_path(file_path: &Path) -> Option<&'static str> {
    match file_path.extension()?.to_str()? {
        "py" => Some("python"),
        "java" => Some("java"),
        "js" | "mjs" => Some("javascript"),
        "tsx" => Some("tsx"),
        "html" => {
            let path_str = file_path.to_string_lossy().to_lowercase();
            if path_str.contains("template") || path_str.contains("django") {
                Some("html")
            } else {
                Some("html")
            }
        },
        _ => None,
    }
}

fn discover_files_by_language_parallel(root_dir: &str) -> Result<HashMap<String, Vec<PathBuf>>> {
    let all_paths: Vec<PathBuf> = WalkDir::new(root_dir)
        .follow_links(false)
        .into_iter()
        .par_bridge()
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                if e.path().is_file() {
                    Some(e.path().to_path_buf())
                } else {
                    None
                }
            })
        })
        .collect();
    
    let estimated_languages = 6;
    let estimated_files_per_lang = if all_paths.is_empty() { 
        50 
    } else { 
        (all_paths.len() / estimated_languages).max(50) 
    };
    
    println!("📂 Discovered {} files total, estimating {} files per language", 
             all_paths.len(), estimated_files_per_lang);
    
    let files_by_language = Arc::new(Mutex::new(
        HashMap::<String, Vec<PathBuf>>::with_capacity(estimated_languages)
    ));
    
    all_paths.par_iter().for_each(|path| {
        if let Some(language) = detect_language_from_path(path) {
            let mut map = files_by_language.lock().unwrap();
            map.entry(language.to_string())
                .or_insert_with(|| Vec::with_capacity(estimated_files_per_lang))
                .push(path.clone());
        }
    });
    
    Ok(Arc::try_unwrap(files_by_language).unwrap().into_inner().unwrap())
}

fn discover_files_by_language_sequential(root_dir: &str) -> Result<HashMap<String, Vec<PathBuf>>> {
    let mut files_by_language = HashMap::with_capacity(6);
    
    for entry in WalkDir::new(root_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().is_file() {
            if let Some(language) = detect_language_from_path(entry.path()) {
                files_by_language
                    .entry(language.to_string())
                    .or_insert_with(|| Vec::with_capacity(100))
                    .push(entry.path().to_path_buf());
            }
        }
    }
    
    Ok(files_by_language)
}

fn get_mode_info(single_threaded: bool, threads: Option<usize>) -> (String, String) {
    let mode = if single_threaded { "single-threaded" } else { "parallel" };
    let thread_info = if let Some(threads) = threads {
        format!(" with {} threads", threads)
    } else {
        String::new()
    };
    (mode.to_string(), thread_info)
}

fn setup_progress_bars(total_files: usize) -> (ProgressBar, ProgressBar) {
    let multi_progress = MultiProgress::new();
    
    let file_progress = multi_progress.add(ProgressBar::new(total_files as u64));
    if let Ok(style) = ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
    {
        file_progress.set_style(style.progress_chars("#>-"));
    }
    file_progress.set_message("Scanning files");
    
    let finding_progress = multi_progress.add(ProgressBar::new(0));
    if let Ok(style) = ProgressStyle::default_bar()
        .template("{spinner:.yellow} Found {pos} vulnerabilities")
    {
        finding_progress.set_style(style);
    }
    
    (file_progress, finding_progress)
}

fn print_findings_json(findings: &[Finding]) {
    match serde_json::to_string_pretty(findings) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error serializing findings to JSON: {}", e),
    }
}

fn print_findings_csv(findings: &[Finding]) {
    println!("file,line,function,finding_type,code");
    for finding in findings {
        let code = finding.code.replace('"', "\"\"");
        println!("{},{},{},{},\"{}\"", 
                finding.file, finding.line, finding.function, finding.finding_type, code);
    }
}

fn print_findings_text(findings: &[Finding], verbose: bool, summary_only: bool) {
    if !summary_only {
        for finding in findings {
            if verbose {
                println!("{}:{} - {} - {} - {}", 
                        finding.file, finding.line, finding.finding_type, 
                        finding.function, finding.code);
            } else {
                println!("{}:{} - {} - {}", 
                        finding.file, finding.line, finding.finding_type, finding.function);
            }
        }
    }
    print_summary(findings);
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(threads) = cli.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(|e| anyhow::anyhow!("Failed to set thread pool size: {}", e))?;
    }

    let start_time = std::time::Instant::now();
    
    let findings = match (&cli.language, &cli.rules_path) {
        (Some(language), Some(rules_path)) => {
            let rules = Rules::load_from_path(rules_path)?;
            let total_rules = ScanningLogic::count_total_rules(&rules);
            let mut scanner = VulnerabilityScanner::new(language, rules)?;

            let (mode, thread_info) = get_mode_info(cli.single_threaded, cli.threads);
            
            println!("🚀 Starting Explicit Scan ({} mode{})!", mode, thread_info);
            println!("📂 Target directory: {}", cli.root_dir);
            println!("🔧 Language: {}", language);
            
            let path = std::path::Path::new(rules_path);
            if path.is_dir() {
                println!("📋 Rules directory: {}", rules_path);
            } else {
                println!("📋 Rules file: {}", rules_path);
            }
            
            println!("🔍 Running scan with {} rules", total_rules);
            println!();

            if cli.single_threaded {
                scanner.find_vulnerabilities_single_threaded(&cli.root_dir, language)?
            } else {
                if cli.root_dir.contains("large") || cli.root_dir.contains("huge") {
                    scanner.find_vulnerabilities_batched(&cli.root_dir, language)?
                } else {
                    scanner.find_vulnerabilities_parallel(&cli.root_dir, language)?
                }
            }
        }
        (None, None) => {
            let (mode, thread_info) = get_mode_info(cli.single_threaded, cli.threads);
            
            println!("🚀 Starting Auto-Detection Scan ({} mode{})!", mode, thread_info);
            println!("📂 Target directory: {}", cli.root_dir);
            
            let discovery_start = std::time::Instant::now();
            let files_by_language = if cli.single_threaded {
                println!("🔍 Using sequential file discovery...");
                discover_files_by_language_sequential(&cli.root_dir)?
            } else {
                println!("🚀 Using parallel file discovery for maximum performance...");
                discover_files_by_language_parallel(&cli.root_dir)?
            };
            let discovery_time = discovery_start.elapsed();
            
            if files_by_language.is_empty() {
                println!("❌ No supported files found in {}", cli.root_dir);
                println!("   Supported file types: .py, .java, .js, .tsx, .html");
                return Ok(());
            }
            
            let detected_languages: Vec<String> = files_by_language.keys().cloned().collect();
            println!("🔍 Detected languages: {} (in {:.2?})", 
                    detected_languages.join(", "), discovery_time);
            
            let total_files: usize = files_by_language.values().map(|files| files.len()).sum();
            let total_findings = Arc::new(AtomicUsize::new(0));
            
            let (file_progress, finding_progress) = if !cli.single_threaded {
                let (fp, fp2) = setup_progress_bars(total_files);
                (Some(fp), Some(fp2))
            } else {
                (None, None)
            };
            
            println!();
            
            let mut all_findings = Vec::with_capacity(total_files / 20);
            let mut total_files_scanned = 0;
            let mut total_rules_loaded = 0;
            
            for (language, files) in files_by_language {
                let rules_dir = format!("rules/{}", language);
                match Rules::load_from_directory(&rules_dir) {
                    Ok(rules) => {
                        let rule_count = ScanningLogic::count_total_rules(&rules);
                        total_rules_loaded += rule_count;
                        
                        println!("🚀 Scanning {} {} files with {} rules...", files.len(), language, rule_count);
                        
                        let mut parser = LanguageParser::new(&language)?;
                        let all_rules = ScanningLogic::get_all_rules(&rules);
                        
                        for file_path in &files {
                            let filepath = file_path.to_string_lossy().to_string();
                            match fs::read(&filepath) {
                                Ok(source) => {
                                    match parser.parse(&source) {
                                        Ok(tree) => {
                                            let findings = ScanningLogic::scan_file_with_rules(
                                                &filepath,
                                                &source,
                                                &tree,
                                                &all_rules,
                                                parser.language_support(),
                                            );
                                            
                                            let finding_count = findings.len();
                                            if finding_count > 0 {
                                                let current_total = total_findings.fetch_add(finding_count, Ordering::Relaxed) + finding_count;
                                                if let Some(ref progress) = finding_progress {
                                                    progress.set_position(current_total as u64);
                                                }
                                            }
                                            
                                            all_findings.extend(findings);
                                            total_files_scanned += 1;
                                            
                                            if let Some(ref progress) = file_progress {
                                                progress.inc(1);
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Failed to parse {}: {}", filepath, e);
                                            if let Some(ref progress) = file_progress {
                                                progress.inc(1);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Failed to read file {}: {}", filepath, e);
                                    if let Some(ref progress) = file_progress {
                                        progress.inc(1);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("⚠️  Failed to load rules for {}: {}", language, e);
                        eprintln!("   Make sure {} directory exists with .ron rule files", rules_dir);
                    }
                }
            }
            
            if let Some(ref progress) = file_progress {
                progress.finish_with_message("Scan complete");
            }
            if let Some(ref progress) = finding_progress {
                progress.finish_with_message("Scan complete");
            }
            
            println!();
            println!("📊 Scanned {} files total with {} rules across {} languages", 
                    total_files_scanned, total_rules_loaded, detected_languages.len());
            println!("⚡ File discovery performance: {:.2?}", discovery_time);
            
            all_findings
        }
        (Some(_), None) => {
            return Err(anyhow::anyhow!(
                "❌ Language provided but no rules path. Please provide both:\n  \
                cargo run -- {} <language> <rules_path>\n  \
                Or use auto-detection:\n  \
                cargo run -- {}", 
                cli.root_dir, cli.root_dir
            ));
        }
        (None, Some(_)) => {
            return Err(anyhow::anyhow!(
                "❌ Rules path provided but no language. Please provide both:\n  \
                cargo run -- {} <language> <rules_path>\n  \
                Or use auto-detection:\n  \
                cargo run -- {}", 
                cli.root_dir, cli.root_dir
            ));
        }
    };

    let duration = start_time.elapsed();
    println!();
    println!("⏱️  Scan completed in {:.2?}", duration);
    println!();

    match cli.output_format.as_str() {
        "json" => print_findings_json(&findings),
        "csv" => print_findings_csv(&findings),
        "text" | _ => print_findings_text(&findings, cli.verbose, cli.summary_only),
    }

    Ok(())
} 