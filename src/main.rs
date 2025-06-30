use anyhow::Result;
use clap::Parser;
use find_vulns::{Cli, CommonUtils, run_explicit_scan, run_auto_detection_scan, run_taint_analysis};
use find_vulns::scanner::core::{print_findings_json, print_findings_csv, print_findings_text, print_summary};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Configure threading if specified
    if let Some(threads) = cli.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(|e| anyhow::anyhow!("Failed to set thread pool size: {}", e))?;
    }

    let start_time = std::time::Instant::now();
    
    // Handle all vulnerability scanning modes with unified flow
    let findings = if cli.taint_analysis {
        run_taint_analysis(&cli)?
    } else {
        // Validate CLI parameters using CommonUtils
        CommonUtils::validate_cli_params(&cli.language, &cli.rules_path)
            .map_err(|_| anyhow::anyhow!(
                "❌ Invalid combination. Please provide both language and rules path:\n  \
                cargo run -- {} <language> <rules_path>\n  \
                Or use auto-detection (no language/rules args):\n  \
                cargo run -- {}", 
                cli.root_dir, cli.root_dir
            ))?;

        match (&cli.language, &cli.rules_path) {
            (Some(_), Some(_)) => run_explicit_scan(&cli)?,
            (None, None) => run_auto_detection_scan(&cli)?,
            _ => unreachable!(), // Validation above ensures this won't happen
        }
    };

    // Output results
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