use anyhow::Result;
use clap::Parser;
use find_vulns::{Cli, Rules, VulnerabilityScanner, print_summary, Finding};
use find_vulns::scanner::ScanningLogic;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use syntect::easy::HighlightLines;
use syntect::highlighting::{Style, ThemeSet};
use syntect::parsing::SyntaxSet;
use syntect::util::LinesWithEndings;

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

fn detect_syntax(file_path: &str) -> &'static str {
    match std::path::Path::new(file_path).extension().and_then(|e| e.to_str()) {
        Some("py") => "Python",
        Some("js") | Some("mjs") => "JavaScript",
        Some("ts") | Some("tsx") => "TypeScript",
        Some("rs") => "Rust",
        Some("java") => "Java",
        Some("html") => "HTML",
        Some("css") => "CSS",
        Some("json") => "JSON",
        Some("md") => "Markdown",
        Some("sh") => "Shell",
        Some("go") => "Go",
        Some("php") => "PHP",
        Some("rb") => "Ruby",
        Some("swift") => "Swift",
        Some("kt") => "Kotlin",
        Some("scala") => "Scala",
        Some("c") => "C",
        Some("cpp") | Some("cc") | Some("cxx") | Some("hpp") => "C++",
        Some("cs") => "C#",
        Some("sql") => "SQL",
        _ => "Plain Text",
    }
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

fn print_findings_text(findings: &[Finding], verbose: bool, summary_only: bool, duration: std::time::Duration) {
    if !summary_only {
        // Initialize syntax highlighting
        let ps = SyntaxSet::load_defaults_newlines();
        let ts = ThemeSet::load_defaults();
        let theme = &ts.themes["base16-ocean.dark"];

        // Pre-sort findings by file and severity for better grouping
        let mut sorted_findings: Vec<_> = findings.iter().collect();
        sorted_findings.sort_by(|a, b| {
            a.file.cmp(&b.file)
                .then(a.severity.cmp(&b.severity))
                .then(a.line.cmp(&b.line))
        });

        // Group findings by file
        let mut current_file = None;
        let mut file_contents = String::new();
        let mut lines = Vec::new();
        let mut syntax = None;

        for finding in sorted_findings {
            // Only read file when it changes
            if current_file != Some(&finding.file) {
                current_file = Some(&finding.file);
                file_contents = match fs::read_to_string(&finding.file) {
                    Ok(contents) => contents,
                    Err(_) => continue,
                };
                lines = file_contents.lines().collect();
                
                // Set up syntax highlighting for the new file
                let syntax_name = detect_syntax(&finding.file);
                syntax = ps.find_syntax_by_name(syntax_name);
                
                println!("\n\x1b[1;34m{}\x1b[0m", finding.file);
            }

            let severity_color = match finding.severity.to_lowercase().as_str() {
                "critical" => "\x1b[31m", // Red
                "high" => "\x1b[31;1m",   // Bright red
                "medium" => "\x1b[33m",   // Yellow
                "low" => "\x1b[32m",      // Green
                _ => "\x1b[0m",           // Default
            };

            let line_num = finding.line;
            let start_line = line_num.saturating_sub(3);
            let end_line = (line_num + 3).min(lines.len());

            println!("");
            println!("    {}{}●\x1b[0m {} on line {}", 
                    severity_color, 
                    severity_color, 
                    finding.finding_type, 
                    line_num);
            println!();

            // Print surrounding context with syntax highlighting
            if let Some(syntax) = syntax {
                let mut h = HighlightLines::new(syntax, theme);
                for i in start_line..end_line {
                    let line = lines[i];
                    let ranges: Vec<(Style, &str)> = h.highlight_line(line, &ps).unwrap_or_default();
                    let prefix = if i + 1 == line_num { "\x1b[31m>>\x1b[0m" } else { "  " };
                    print!("    {}{:4} | ", prefix, i + 1);
                    
                    for (style, text) in ranges {
                        let fg = style.foreground;
                        print!("\x1b[38;2;{};{};{}m{}\x1b[0m",
                            fg.r, fg.g, fg.b, text);
                    }
                    println!();
                }
            } else {
                // Fallback to plain text if syntax highlighting fails
                for i in start_line..end_line {
                    let prefix = if i + 1 == line_num { "\x1b[31m>>\x1b[0m" } else { "  " };
                    println!("    {}{:4} | {}", prefix, i + 1, lines[i]);
                }
            }
            println!();
        }
    }
    print_summary(findings, duration);
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
                scanner.find_vulnerabilities_parallel(&cli.root_dir, language, true)?
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
            
            use rayon::prelude::*;

            // Convert to Vec to own data
            let lang_jobs: Vec<(String, Vec<PathBuf>)> = files_by_language.into_iter().collect();

            let processed_files = Arc::new(AtomicUsize::new(0));
            let progress_handle = if let Some(ref bar) = file_progress {
                let bar_clone = bar.clone();
                let proc_clone = Arc::clone(&processed_files);
                Some(std::thread::spawn(move || {
                    use std::time::Duration;
                    loop {
                        let val = proc_clone.load(Ordering::Relaxed) as u64;
                        bar_clone.set_position(val);
                        if val >= bar_clone.length().unwrap_or(0) { break; }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }))
            } else { None };

            let total_rules_loaded = Arc::new(AtomicUsize::new(0));
            let all_findings: Vec<Finding> = lang_jobs
                .par_iter()
                .flat_map(|(language, files)| {
                    let rules_dir = format!("rules/{}", language);
                    match Rules::load_from_directory(&rules_dir) {
                        Ok(rules) => {
                            let rule_count = ScanningLogic::count_total_rules(&rules);
                            total_rules_loaded.fetch_add(rule_count, Ordering::Relaxed);
                            
                            println!("🚀 Scanning {} {} files with {} rules...", files.len(), language, rule_count);
                            
                            let scanner = VulnerabilityScanner::new(&language, rules).expect("scanner");
                            
                            match scanner.find_vulnerabilities_parallel(&cli.root_dir, &language, false) {
                                Ok(fnds) => {
                                    processed_files.fetch_add(files.len(), Ordering::Relaxed);
                                    if let Some(ref fbar) = finding_progress {
                                        if !fnds.is_empty() {
                                            let pos = total_findings.fetch_add(fnds.len(), Ordering::Relaxed) + fnds.len();
                                            fbar.set_position(pos as u64);
                                        }
                                    }
                                    fnds
                                }
                                Err(e) => {
                                    eprintln!("Failed scanning {}: {}", language, e);
                                    Vec::new()
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("⚠️  Failed to load rules for {}: {}", language, e);
                            Vec::new()
                        }
                    }
                })
                .collect();

            if let Some(handle) = progress_handle { let _ = handle.join(); }
            if let Some(ref bar) = file_progress { bar.finish_with_message("Scan complete"); }
            if let Some(ref bar) = finding_progress { bar.finish_with_message("Scan complete"); }
            
            println!();
            println!("📊 Scanned {} files total with {} rules across {} languages", 
                    total_files, total_rules_loaded.load(Ordering::Relaxed), detected_languages.len());
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
        "text" | _ => print_findings_text(&findings, cli.verbose, cli.summary_only, duration),
    }

    Ok(())
} 