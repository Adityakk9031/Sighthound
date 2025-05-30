use clap::Parser;

#[derive(Parser)]
#[command(
    name = "find_vulns",
    about = "A fast vulnerability scanner for source code",
    long_about = "Corgea Greppy - A high-performance vulnerability scanner that uses tree-sitter for AST-based analysis"
)]
pub struct Cli {
    /// Root directory to scan
    pub root_dir: String,
    
    /// Language to scan (currently only 'python' is supported)
    pub language: String,
    
    /// Rules file (JSON format)
    pub rules_file: String,
    
    /// Output format (text, json, csv)
    #[arg(short, long, default_value = "text")]
    pub output_format: String,
    
    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
    
    /// Only show summary
    #[arg(short, long)]
    pub summary_only: bool,
} 