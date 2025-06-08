use anyhow::Result;
use clap::Parser;
use find_vulns::{Cli, Rules, VulnerabilityScanner, print_summary, Finding};

fn print_findings_json(findings: &[Finding]) {
    match serde_json::to_string_pretty(findings) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error serializing findings to JSON: {}", e),
    }
}

fn print_findings_csv(findings: &[Finding]) {
    println!("file,line,function,finding_type,code");
    for finding in findings {
        let code = finding.code.replace('"', "\"\""); // Escape quotes for CSV
        println!("{},{},{},{},\"{}\"", 
                finding.file, finding.line, finding.function, finding.finding_type, code);
    }
}

fn print_findings_text(findings: &[Finding], verbose: bool, summary_only: bool) {
    if !summary_only {
        // Print individual findings
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

// Helper function to count the total number of rules
fn count_total_rules(rules: &Rules) -> usize {
    let mut count = 0;
    
    if let Some(rules) = &rules.injection_sinks { count += rules.len(); }
    if let Some(rules) = &rules.crypto_rules { count += rules.len(); }
    if let Some(rules) = &rules.path_traversal { count += rules.len(); }
    if let Some(rules) = &rules.weak_random { count += rules.len(); }
    if let Some(rules) = &rules.hardcoded_secrets { count += rules.len(); }
    if let Some(rules) = &rules.malware_detection { count += rules.len(); }
    
    // Add other rule groups
    for rules in rules.other.values() {
        count += rules.len();
    }
    
    count
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Configure thread pool if specified
    if let Some(threads) = cli.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(|e| anyhow::anyhow!("Failed to set thread pool size: {}", e))?;
    }

    let rules = Rules::load_from_path(&cli.rules_path)?;
    let total_rules = count_total_rules(&rules);
    let mut scanner = VulnerabilityScanner::new(&cli.language, rules)?;

    let mode = if cli.single_threaded { "single-threaded" } else { "parallel" };
    let thread_info = if let Some(threads) = cli.threads {
        format!(" with {} threads", threads)
    } else {
        String::new()
    };
    
    println!("🚀 Starting Corgea Greppy Scan ({} mode{})!", mode, thread_info);
    println!("📂 Target directory: {}", cli.root_dir);
    println!("🔧 Language: {}", cli.language);
    
    // Determine if rules_path is a file or directory for display
    let path = std::path::Path::new(&cli.rules_path);
    if path.is_dir() {
        println!("📋 Rules directory: {}", cli.rules_path);
    } else {
        println!("📋 Rules file: {}", cli.rules_path);
    }
    
    println!("🔍 Running scan with {} rules", total_rules);
    println!();

    let start_time = std::time::Instant::now();
    
    let findings = if cli.single_threaded {
        scanner.find_vulnerabilities_single_threaded(&cli.root_dir, &cli.language)?
    } else {
        scanner.find_vulnerabilities_parallel(&cli.root_dir, &cli.language)?
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