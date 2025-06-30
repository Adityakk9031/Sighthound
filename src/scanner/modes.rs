use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::path::PathBuf;

use crate::cli::Cli;
use crate::rules::Rules;
use crate::scanner::{VulnerabilityScanner, Finding, TaintAnalyzer};
use crate::scanner::core::ScanningLogic;
use crate::scanner::utils::{discover_files_by_language, discover_files_by_language_parallel, discover_files_by_language_sequential};
use crate::scanner::core::ProgressManager;
use crate::scanner::taint::merge_taint_results;
use crate::scanner::{TaintAnalysisResult, TaintSummary};

/// Unified scan configuration and execution context
#[derive(Debug)]
struct ScanContext {
    root_dir: String,
    single_threaded: bool,
    skip_minified: bool,
    discovery_time: std::time::Duration,
    total_files: usize,
    detected_languages: Vec<String>,
}

impl ScanContext {
    /// Initialize scan context with file discovery
    fn new(cli: &Cli) -> Result<Self> {
        let discovery_start = std::time::Instant::now();
        
        let parallel = !cli.single_threaded;
        if parallel {
            println!("🚀 Using parallel file discovery for maximum performance...");
        } else {
            println!("🔍 Using sequential file discovery...");
        }
        
        let files_by_language = discover_files_by_language(&cli.root_dir, parallel)?;
        let discovery_time = discovery_start.elapsed();
        
        if files_by_language.is_empty() {
            println!("❌ No supported files found in {}", cli.root_dir);
            println!("   Supported file types: .py, .java, .js, .tsx, .html");
            return Err(anyhow::anyhow!("No supported files found"));
        }
        
        let detected_languages: Vec<String> = files_by_language.keys().cloned().collect();
        let total_files: usize = files_by_language.values().map(|files| files.len()).sum();
        
        println!("🔍 Detected languages: {} (in {:.2?})", 
                detected_languages.join(", "), discovery_time);
        
        Ok(Self {
            root_dir: cli.root_dir.clone(),
            single_threaded: cli.single_threaded,
            skip_minified: cli.skip_minified.unwrap_or(true),
            discovery_time,
            total_files,
            detected_languages,
        })
    }
    
    /// Get mode information string for display
    fn get_mode_info(&self, threads: Option<usize>) -> (String, String) {
        let mode = if self.single_threaded { "single-threaded" } else { "parallel" };
        let thread_info = if let Some(threads) = threads {
            format!(" with {} threads", threads)
        } else {
            String::new()
        };
        (mode.to_string(), thread_info)
    }
    
    /// Create and configure progress manager
    fn create_progress_manager(&self) -> ProgressManager {
        ProgressManager::new(self.total_files)
    }
    
    /// Print performance summary
    fn print_performance_summary(&self, rule_count: usize, scan_duration: std::time::Duration) {
        println!();
        println!("📊 Scanned {} files total with {} rules across {} languages", 
                self.total_files, rule_count, self.detected_languages.len());
        println!("⚡ File discovery: {:.2?} | Analysis: {:.2?}", 
                self.discovery_time, scan_duration.saturating_sub(self.discovery_time));
    }
}

/// Load rules based on CLI configuration
fn load_rules(cli: &Cli, context: &ScanContext) -> Result<Rules> {
    match (&cli.language, &cli.rules_path) {
        (Some(_language), Some(rules_path)) => Rules::load_from_path(rules_path),
        (None, None) => {
            // Auto-detect and merge rules from all languages
            let mut all_rules = Vec::new();
            
            for language in &context.detected_languages {
                let rules_dir = format!("rules/{}", language);
                if let Ok(rules) = Rules::load_from_directory(&rules_dir) {
                    all_rules.push(rules);
                }
            }
            
            if all_rules.is_empty() {
                return Err(anyhow::anyhow!("No rules found for detected languages"));
            }
            
            Rules::merge_rules(all_rules)
        }
        _ => Err(anyhow::anyhow!("Invalid CLI configuration")),
    }
}

/// Run explicit scan mode (language and rules specified)
pub fn run_explicit_scan(cli: &Cli) -> Result<Vec<Finding>> {
    let language = cli.language.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Language required for explicit scan"))?;
    let rules_path = cli.rules_path.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Rules path required for explicit scan"))?;
    
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

    // Use unified configuration for display
    let mode = if cli.single_threaded { "single-threaded" } else { "parallel" };
    let thread_info = if let Some(threads) = cli.threads {
        format!(" with {} threads", threads)
    } else {
        String::new()
    };
    
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
    let scan_start = std::time::Instant::now();
    
    // Initialize unified scan context
    let context = ScanContext::new(cli)?;
    let (mode, thread_info) = context.get_mode_info(cli.threads);
    
    println!("🚀 Starting Auto-Detection Scan ({} mode{})!", mode, thread_info);
    println!("📂 Target directory: {}", cli.root_dir);
    
    // Rediscover files by language for actual processing (context only used for validation)
    let files_by_language = if cli.single_threaded {
        discover_files_by_language_sequential(&cli.root_dir)?
    } else {
        discover_files_by_language_parallel(&cli.root_dir)?
    };
    
    let total_findings = Arc::new(AtomicUsize::new(0));
    let mut progress_manager = if !cli.single_threaded {
        Some(context.create_progress_manager())
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
    
    // Process languages sequentially to avoid nested parallelism deadlocks
    for (language, files) in lang_jobs {
        let rules_dir = format!("rules/{}", language);
        match Rules::load_from_directory(&rules_dir) {
            Ok(rules) => {
                let rule_count = ScanningLogic::count_total_rules(&rules);
                total_rules_loaded.fetch_add(rule_count, Ordering::Relaxed);
                
                if let Some(ref progress) = progress_manager {
                    progress.set_message(format!("| scanning {} ({}/{} files)", language, files.len(), context.total_files));
                }
                
                let scanner = VulnerabilityScanner::with_skip_minified(
                    &language, 
                    rules, 
                    context.skip_minified
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
                        eprintln!("⚠️  Failed to scan {}: {}", language, e);
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
    
    // Use unified performance reporting
    let scan_duration = scan_start.elapsed();
    context.print_performance_summary(total_rules_loaded.load(Ordering::Relaxed), scan_duration);
    
    Ok(all_findings)
}

/// Run taint analysis mode
pub fn run_taint_analysis(cli: &Cli) -> Result<Vec<Finding>> {
    println!("🔍 Taint analysis enabled - tracking data flows from sources to sinks");
    
    let scan_start = std::time::Instant::now();
    
    // Initialize unified scan context
    let context = ScanContext::new(cli)?;
    
    // Load rules using unified pattern
    let rules = load_rules(cli, &context)?;
    
    // Check if we have taint flow rules (unified only)
    let taint_rules_count = rules.rules.iter().filter(|r| r.is_taint_rule()).count();
    
    if taint_rules_count == 0 {
        return Err(anyhow::anyhow!("No taint flow rules found. Please ensure your rules contain 'rules' with mode='taint'."));
    }
    
    println!("🔍 Starting Taint Analysis Mode");
    println!("📂 Target directory: {}", cli.root_dir);
    println!("🔧 Loaded {} taint flow rules", taint_rules_count);
    println!("📁 Total files to analyze: {}", context.total_files);
    println!();
    
    // Rediscover files for processing
    let files_by_language = discover_files_by_language_sequential(&cli.root_dir)?;
    
    // Enhanced multi-file taint analysis with cross-file flow detection
    let mut analyzer = TaintAnalyzer::new(rules);
    let mut all_results = Vec::new();
    let mut all_sources = Vec::new();
    let mut all_sinks = Vec::new();
    
    // Setup progress tracking using unified pattern
    let mut progress_manager = context.create_progress_manager();
    let processed_files = Arc::new(AtomicUsize::new(0));
    let total_flows = Arc::new(AtomicUsize::new(0));
    
    // Start progress tracking
    progress_manager.start_tracking(Arc::clone(&processed_files), Arc::clone(&total_flows));
    
    println!("🔍 Phase 1: Analyzing individual files for sources and sinks...");
    
    for (language, files) in files_by_language {
        if let Ok(mut parser) = crate::parser::LanguageParser::new(&language) {
            // Update progress bar message to show current language
            progress_manager.set_message(format!("| analyzing {} ({} files)", language, files.len()));
            
            for file_path in files {
                let file_path_str = file_path.to_string_lossy();
                
                if let Ok(source) = std::fs::read(&file_path) {
                    if let Ok(tree) = parser.parse(&source) {
                        let result = analyzer.analyze_file(&file_path_str, &source, &tree, parser.language_support());
                        
                        // Collect all sources and sinks for cross-file analysis
                        all_sources.extend(result.sources.clone());
                        all_sinks.extend(result.sinks.clone());
                        
                        if !result.flows.is_empty() {
                            total_flows.fetch_add(result.flows.len(), Ordering::Relaxed);
                        }
                        all_results.push(result);
                    }
                }
                
                // Update processed files counter
                processed_files.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    
    // Phase 2: Cross-file taint analysis
    println!("🌐 Phase 2: Analyzing cross-file taint flows...");
    progress_manager.set_message("| analyzing cross-file flows".to_string());
    
    let cross_file_flows = analyzer.analyze_cross_file(&all_sources, &all_sinks);
    if !cross_file_flows.is_empty() {
        println!("🎯 Found {} potential cross-file taint flows", cross_file_flows.len());
        total_flows.fetch_add(cross_file_flows.len(), Ordering::Relaxed);
        
        // Add cross-file flows to the first result or create a new one
        if let Some(first_result) = all_results.first_mut() {
            first_result.flows.extend(cross_file_flows);
        } else {
            // Create a new result for cross-file flows
            let cross_file_result = TaintAnalysisResult {
                flows: cross_file_flows,
                summary: TaintSummary {
                    total_flows: 0, // Will be recalculated in merge
                    unsanitized_flows: 0,
                    sanitized_flows: 0,
                    cross_file_flows: 0,
                    files_analyzed: 0,
                    functions_analyzed: 0,
                },
                imports: Vec::new(),
                exports: Vec::new(),
                cross_file_flows: Vec::new(),
                sources: Vec::new(),
                sinks: Vec::new(),
            };
            all_results.push(cross_file_result);
        }
    }
    
    // Clean up progress tracking
    progress_manager.stop();
    
    // Merge all results with enhanced cross-file support
    let merged_result = merge_taint_results(all_results);
    let scan_duration = scan_start.elapsed();
    
    // Use unified performance reporting
    context.print_performance_summary(taint_rules_count, scan_duration);
    println!("⏱️  Taint analysis completed in {:.2?}", scan_duration);
    
    // Convert to unified Finding format
    Ok(merged_result.to_findings())
}

 