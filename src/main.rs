use anyhow::Result;
use clap::Parser;
use sighthound::scanner::core::{print_findings_csv, print_findings_json, print_findings_text};
use sighthound::{
    run_auto_detection_scan, run_explicit_scan, run_taint_analysis,
    run_taint_analysis_with_verbosity, Cli, CommonUtils, Finding,
};

fn print_version_info() {
    println!("sighthound {}", env!("CARGO_PKG_VERSION"));
    println!("Built from commit: {}", option_env!("GIT_HASH").unwrap_or("unknown"));
    println!("Build date: {}", option_env!("BUILD_DATE").unwrap_or("unknown"));
}

fn require_root_dir(cli: &Cli) -> Result<&String> {
    cli.root_dir.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Root directory is required for scanning. Use --help for usage information."
        )
    })
}

fn init_logging(cli: &Cli) {
    // Initialize logger (respect RUST_LOG or --verbose flag)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(if cli.verbose {
        "debug"
    } else {
        "info"
    }))
    .init();
}

fn configure_thread_pool(cli: &Cli) -> Result<()> {
    if let Some(threads) = cli.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(|e| anyhow::anyhow!("Failed to set thread pool size: {}", e))?;
    }
    Ok(())
}

fn validate_scan_flags(cli: &Cli) -> Result<()> {
    if cli.taint_analysis && cli.simple_analysis {
        return Err(anyhow::anyhow!("Cannot specify both --taint-analysis and --simple-analysis. Use one or neither (default: both modes)."));
    }
    Ok(())
}

fn validate_cli_params(cli: &Cli, root_dir: &str) -> Result<()> {
    CommonUtils::validate_cli_params(
        &cli.language,
        &cli.rules_path,
        cli.use_embedded_rules,
        cli.use_file_rules,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "❌ Invalid parameter combination: {}\n\n\
            Valid usage:\n  \
            • Explicit mode with embedded rules (default): cargo run -- {} <language>\n  \
            • Explicit mode with file rules: cargo run -- {} <language> <rules_path> --use-file-rules\n  \
            • Auto-detection mode with embedded rules (default): cargo run -- {}\n  \
            • Auto-detection mode with file rules: cargo run -- {} --use-file-rules\n  \
            • Custom rules directory: cargo run -- {} --rules-dir <custom_rules_dir> --use-file-rules",
            e, root_dir, root_dir, root_dir, root_dir, root_dir
        )
    })
}

/// Run "simple" (non-taint) analysis using explicit or auto-detected language/rules.
fn run_simple_analysis(
    cli: &Cli,
    root_dir: &str,
    show_progress: bool,
    should_use_embedded: bool,
) -> Result<Vec<Finding>> {
    match (&cli.language, &cli.rules_path, should_use_embedded) {
        (Some(_), Some(_), false) => run_explicit_scan(cli, root_dir, show_progress),
        (Some(_), None, true) => run_explicit_scan(cli, root_dir, show_progress),
        (None, None, _) => run_auto_detection_scan(cli, root_dir, show_progress),
        _ => unreachable!(), // Validation above ensures this won't happen
    }
}

/// Dispatch to the requested scan mode(s): taint-only, simple-only, or both (default).
fn run_selected_analysis(
    cli: &Cli,
    root_dir: &str,
    show_progress: bool,
    should_use_embedded: bool,
) -> Result<Vec<Finding>> {
    if cli.taint_analysis {
        // Only taint analysis
        if show_progress {
            println!("🔍 Running taint analysis mode only");
        }
        run_taint_analysis(cli, root_dir, show_progress)
    } else if cli.simple_analysis {
        // Only simple analysis
        if show_progress {
            println!("🔍 Running simple analysis mode only");
        }
        run_simple_analysis(cli, root_dir, show_progress, should_use_embedded)
    } else {
        // Default: Run both simple and taint analysis
        if show_progress {
            println!("🔍 Running comprehensive analysis (both simple and taint modes)");
        }

        // Run simple analysis first
        let mut simple_findings =
            run_simple_analysis(cli, root_dir, show_progress, should_use_embedded)?;

        // Run taint analysis second (less verbose in combined mode)
        let mut taint_findings =
            run_taint_analysis_with_verbosity(cli, root_dir, show_progress, false)?;

        // Combine findings
        simple_findings.append(&mut taint_findings);
        Ok(simple_findings)
    }
}

fn print_completion_banner(show_progress: bool, duration: std::time::Duration) {
    // Only show completion message for text output
    if show_progress {
        println!();
        println!("⏱️  Scan completed in {:.2?}", duration);
        println!();
    }
}

fn output_findings(cli: &Cli, findings: &[Finding], duration: std::time::Duration) {
    match cli.output_format.as_str() {
        "json" => print_findings_json(findings),
        "csv" => print_findings_csv(findings),
        _ => print_findings_text(findings, cli.verbose, cli.summary_only, duration),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle version flag
    if cli.version {
        print_version_info();
        return Ok(());
    }

    // Check if root_dir is provided (required for actual scanning)
    let root_dir = require_root_dir(&cli)?;

    init_logging(&cli);
    // Configure threading if specified
    configure_thread_pool(&cli)?;

    let start_time = std::time::Instant::now();

    // Determine if we should show progress (suppress for structured output formats)
    let show_progress = !matches!(cli.output_format.as_str(), "json" | "csv");

    // Validate CLI parameters
    validate_scan_flags(&cli)?;

    // Resolve the actual embedded rules setting (use_file_rules overrides use_embedded_rules)
    let should_use_embedded = cli.use_embedded_rules && !cli.use_file_rules;

    // Validate CLI parameters using CommonUtils
    validate_cli_params(&cli, root_dir)?;

    // Handle all vulnerability scanning modes with unified flow
    let findings = run_selected_analysis(&cli, root_dir, show_progress, should_use_embedded)?;

    // Output results
    let duration = start_time.elapsed();

    print_completion_banner(show_progress, duration);
    output_findings(&cli, &findings, duration);

    Ok(())
}
