use clap::Parser;

#[derive(Parser)]
#[command(
    name = "find_vulns",
    about = "A fast vulnerability scanner for source code",
    long_about = "Corgea Greppy - A high-performance vulnerability scanner that uses tree-sitter for AST-based analysis with parallel processing support.\n\nSupports both explicit mode (specify language and rules) and auto-detection mode (automatically detect file types and load appropriate rules). Rules must be in RON format."
)]
pub struct Cli {
    /// Root directory to scan
    #[arg(help = "Root directory to scan for vulnerabilities")]
    pub root_dir: String,
    
    /// Language to scan (optional - triggers explicit mode when used with rules_path)
    #[arg(help = "Programming language to scan (python, java, javascript, tsx, html, django)")]
    pub language: Option<String>,
    
    /// Rules file or directory path (optional - triggers explicit mode when used with language)
    #[arg(help = "Path to rules file (.ron) or directory containing multiple .ron rule files")]
    pub rules_path: Option<String>,
    
    /// Output format (text, json, csv)
    #[arg(short, long, default_value = "text", help = "Output format: text, json, or csv")]
    pub output_format: String,
    
    /// Verbose output
    #[arg(short, long, help = "Enable verbose output showing more details")]
    pub verbose: bool,
    
    /// Only show summary
    #[arg(short, long, help = "Only show vulnerability summary without individual findings")]
    pub summary_only: bool,

    /// Disable parallel processing (use single-threaded mode)
    #[arg(long, help = "Disable parallel processing for debugging or specific use cases")]
    pub single_threaded: bool,

    /// Number of threads to use for parallel processing (default: CPU cores)
    #[arg(long, help = "Number of threads for parallel processing (default: auto-detect CPU cores)")]
    pub threads: Option<usize>,

    /// Enable taint analysis mode
    #[arg(long, help = "Enable taint analysis to track data flows from sources to sinks")]
    pub taint_analysis: bool,

    /// Skip minified JavaScript files (default: true)
    #[arg(long, help = "Skip minified JavaScript files during scanning")]
    pub skip_minified: Option<bool>,
} 