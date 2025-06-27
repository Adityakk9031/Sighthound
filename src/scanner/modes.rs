use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::path::PathBuf;
use crate::cli::Cli;
use crate::rules::Rules;
use crate::scanner::{VulnerabilityScanner, Finding, TaintAnalyzer};
use crate::scanner::shared::ScanningLogic;
use crate::scanner::utils::{discover_files_by_language_parallel, discover_files_by_language_sequential};
use crate::scanner::core::ProgressManager;
use crate::scanner::taint::{print_taint_analysis_json, print_taint_analysis_text, merge_taint_results};

/// Run explicit scan mode (language and rules specified)
pub fn run_explicit_scan(cli: &Cli) -> Result<Vec<Finding>> {
    let language = cli.language.as_ref().unwrap();
    let rules_path = cli.rules_path.as_ref().unwrap();
    
    let rules = Rules::load_from_path(rules_path)?;
    let total_rules = ScanningLogic::count_total_rules(&rules);
    
    // Configure minified file skipping
    let skip_minified = cli.skip_minified.unwrap_or(true);
    let scanner = VulnerabilityScanner::with_skip_minified(
        language, 
        rules, 
        skip_minified
    )?;
    
    if !skip_minified {
        println!("⚠️  Minified file skipping disabled - this may increase scan time and false positives");
    }

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

    scanner.find_vulnerabilities_parallel(&cli.root_dir, language, true)
}

/// Run auto-detection scan mode (automatically detect languages and load rules)
pub fn run_auto_detection_scan(cli: &Cli) -> Result<Vec<Finding>> {
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
        return Ok(Vec::new());
    }
    
    let detected_languages: Vec<String> = files_by_language.keys().cloned().collect();
    println!("🔍 Detected languages: {} (in {:.2?})", 
            detected_languages.join(", "), discovery_time);
    
    let total_files: usize = files_by_language.values().map(|files| files.len()).sum();
    let total_findings = Arc::new(AtomicUsize::new(0));
    
    let mut progress_manager = if !cli.single_threaded {
        Some(ProgressManager::new(total_files))
    } else { None };
    
    println!();
    
    // Convert to Vec to own data
    let lang_jobs: Vec<(String, Vec<PathBuf>)> = files_by_language.into_iter().collect();

    let processed_files = Arc::new(AtomicUsize::new(0));
    
    // Start progress tracking
    if let Some(ref mut progress) = progress_manager {
        progress.start_tracking(Arc::clone(&processed_files), Arc::clone(&total_findings));
    }

    let total_rules_loaded = Arc::new(AtomicUsize::new(0));
    let mut all_findings = Vec::new();
    
    // Configure minified file skipping for auto-detection
    let skip_minified = cli.skip_minified.unwrap_or(true);
    
    // Process languages sequentially to avoid nested parallelism deadlocks
    for (language, files) in lang_jobs {
        let rules_dir = format!("rules/{}", language);
        match Rules::load_from_directory(&rules_dir) {
            Ok(rules) => {
                let rule_count = ScanningLogic::count_total_rules(&rules);
                total_rules_loaded.fetch_add(rule_count, Ordering::Relaxed);
                
                if let Some(ref progress) = progress_manager {
                    progress.set_message(format!("| scanning {} ({}/{} files)", language, files.len(), total_files));
                }
                
                let scanner = VulnerabilityScanner::with_skip_minified(
                    &language, 
                    rules, 
                    skip_minified
                ).expect("scanner");
                
                match scanner.find_vulnerabilities_parallel(&cli.root_dir, &language, false) {
                    Ok(fnds) => {
                        processed_files.fetch_add(files.len(), Ordering::Relaxed);
                        if !fnds.is_empty() {
                            total_findings.fetch_add(fnds.len(), Ordering::Relaxed);
                        }
                        all_findings.extend(fnds);
                    }
                    Err(e) => {
                        eprintln!("⚠️  Failed to load rules for {}: {}", language, e);
                    }
                }
            }
            Err(e) => {
                eprintln!("⚠️  Failed to load rules for {}: {}", language, e);
            }
        }
    }

    // Stop progress tracking
    if let Some(mut progress) = progress_manager {
        progress.stop();
    }
    
    println!();
    println!("📊 Scanned {} files total with {} rules across {} languages", 
            total_files, total_rules_loaded.load(Ordering::Relaxed), detected_languages.len());
    println!("⚡ File discovery performance: {:.2?}", discovery_time);
    
    Ok(all_findings)
}

/// Run taint analysis mode
pub fn run_taint_analysis(cli: &Cli) -> Result<()> {
    println!("🔍 Taint analysis enabled - tracking data flows from sources to sinks");
    
    // Run taint analysis mode
    let rules = match (&cli.language, &cli.rules_path) {
        (Some(_language), Some(rules_path)) => Rules::load_from_path(rules_path)?,
        (None, None) => {
            // Auto-detect and merge rules from all languages
            let files_by_language = discover_files_by_language_sequential(&cli.root_dir)?;
            let mut all_rules = Vec::new();
            
            for language in files_by_language.keys() {
                let rules_dir = format!("rules/{}", language);
                if let Ok(rules) = Rules::load_from_directory(&rules_dir) {
                    all_rules.push(rules);
                }
            }
            
            if all_rules.is_empty() {
                return Err(anyhow::anyhow!("No taint flow rules found for analysis"));
            }
            
            Rules::merge_rules(all_rules)?
        }
        _ => return Err(anyhow::anyhow!("For taint analysis, please provide both language and rules path, or use auto-detection")),
    };
    
    // Check if we have taint flow rules (unified only)
    let taint_rules_count = rules.rules.iter().filter(|r| r.is_taint_rule()).count();
    
    if taint_rules_count == 0 {
        return Err(anyhow::anyhow!("No taint flow rules found. Please ensure your rules contain 'rules' with mode='taint'."));
    }
    
    println!("🔍 Starting Taint Analysis Mode");
    println!("📂 Target directory: {}", cli.root_dir);
    
    let taint_flows_count = taint_rules_count;
    println!("🔧 Loaded {} taint flow rules", taint_flows_count);
    
    // File discovery with timing and feedback
    let discovery_start = std::time::Instant::now();
    println!();
    println!("🔍 Discovering files for taint analysis...");
    
    // Analyze files by language
    let files_by_language = discover_files_by_language_sequential(&cli.root_dir)?;
    let discovery_time = discovery_start.elapsed();
    
    if files_by_language.is_empty() {
        println!("❌ No supported files found in {}", cli.root_dir);
        println!("   Supported file types: .py, .java, .js, .tsx, .html");
        return Ok(());
    }
    
    let total_files: usize = files_by_language.values().map(|files| files.len()).sum();
    let detected_languages: Vec<String> = files_by_language.keys().cloned().collect();
    
    println!("🔍 Detected languages: {} (in {:.2?})", 
            detected_languages.join(", "), discovery_time);
    println!("📁 Total files to analyze: {}", total_files);
    println!();
    
    // Note: Taint analysis doesn't currently use VulnerabilityScanner's PreFilter,
    // but it could be extended in the future to support minified file filtering
    let mut analyzer = TaintAnalyzer::new(rules);
    let mut all_results = Vec::new();
    
    // Setup progress tracking
    let mut progress_manager = ProgressManager::new(total_files);
    let processed_files = Arc::new(AtomicUsize::new(0));
    let total_flows = Arc::new(AtomicUsize::new(0));
    
    // Start progress tracking
    progress_manager.start_tracking(Arc::clone(&processed_files), Arc::clone(&total_flows));
    
    for (language, files) in files_by_language {
        if let Ok(mut parser) = crate::parser::LanguageParser::new(&language) {
            // Update progress bar message to show current language
            progress_manager.set_message(format!("| analyzing {} ({} files)", language, files.len()));
            
            for file_path in files {
                let file_path_str = file_path.to_string_lossy();
                
                if let Ok(source) = std::fs::read(&file_path) {
                    if let Ok(tree) = parser.parse(&source) {
                        let result = analyzer.analyze_file(&file_path_str, &source, &tree, parser.language_support());
                        if !result.flows.is_empty() {
                            total_flows.fetch_add(result.flows.len(), Ordering::Relaxed);
                            all_results.push(result);
                        }
                    }
                }
                
                // Update processed files counter
                processed_files.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    
    // Clean up progress tracking
    progress_manager.stop();
    
    // Merge all results
    let merged_result = merge_taint_results(all_results);
    let total_duration = discovery_start.elapsed();
    let analysis_time = total_duration.saturating_sub(discovery_time);
    
    // Enhanced summary with performance metrics
    println!();
    println!("📊 Analyzed {} files with {} taint flow rules across {} languages", 
            total_files, taint_flows_count, detected_languages.len());
    println!("⚡ File discovery: {:.2?} | Analysis: {:.2?}", 
            discovery_time, analysis_time);
    
    println!("⏱️  Taint analysis completed in {:.2?}", total_duration);
    println!();
    
    match cli.output_format.as_str() {
        "json" => print_taint_analysis_json(&merged_result),
        "text" | _ => print_taint_analysis_text(&merged_result, total_duration),
    }
    
    Ok(())
}

/// Get mode information string
fn get_mode_info(single_threaded: bool, threads: Option<usize>) -> (String, String) {
    let mode = if single_threaded { "single-threaded" } else { "parallel" };
    let thread_info = if let Some(threads) = threads {
        format!(" with {} threads", threads)
    } else {
        String::new()
    };
    (mode.to_string(), thread_info)
} 