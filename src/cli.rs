use clap::Parser;

#[derive(Parser)]
#[command(
    name = "find_vulns",
    about = "A fast vulnerability scanner for source code",
    long_about = "Corgea Greppy - A high-performance vulnerability scanner that uses tree-sitter for AST-based analysis with parallel processing support.\n\nSupports both single rule files and directories containing multiple rule files for modular rule management. Rules must be in RON format."
)]
pub struct Cli {
    /// Root directory to scan
    #[arg(help = "Root directory to scan for vulnerabilities")]
    pub root_dir: String,
    
    /// Language to scan (currently only 'python' is supported)
    #[arg(help = "Programming language to scan (currently: python)")]
    pub language: String,
    
    /// Rules file or directory path (RON format only)
    /// If a directory is provided, all .ron files will be loaded and merged
    #[arg(help = "Path to rules file (.ron) or directory containing multiple .ron rule files")]
    pub rules_path: String,
    
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
} 