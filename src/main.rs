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

fn main() -> Result<()> {
    let cli = Cli::parse();

    let rules = Rules::load_from_file(&cli.rules_file)?;
    let mut scanner = VulnerabilityScanner::new(&cli.language, rules)?;

    println!("Starting Corgea Greppy Scan! -----------------");

    let findings = scanner.find_vulnerabilities(&cli.root_dir, &cli.language)?;

    match cli.output_format.as_str() {
        "json" => print_findings_json(&findings),
        "csv" => print_findings_csv(&findings),
        "text" | _ => print_findings_text(&findings, cli.verbose, cli.summary_only),
    }

    Ok(())
} 