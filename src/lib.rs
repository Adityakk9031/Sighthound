pub mod cli;
pub mod language;
pub mod parser;
pub mod rules;
pub mod scanner;
pub mod skip;

// Re-export the main types and functions that main.rs needs
pub use cli::Cli;
pub use rules::Rules;
pub use scanner::{VulnerabilityScanner, print_summary, Finding, 
                  print_findings_json, print_findings_csv, print_findings_text,
                  run_explicit_scan, run_auto_detection_scan, run_taint_analysis};

// Re-export commonly used functions for the library
pub use parser::{traverse_calls_only, get_node_text_slice};
pub use rules::{match_pattern, check_for_injection_pattern, Condition};