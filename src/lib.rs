pub mod cli;
pub mod common;
pub mod config;
pub mod language;
pub mod models;
pub mod parser;
pub mod rules;
pub mod scanner;
pub mod skip;

// Re-export the main types and functions that main.rs needs
pub use scanner::{print_findings_json, print_findings_csv, print_findings_text,
                  run_explicit_scan, run_auto_detection_scan, run_taint_analysis};

// Re-export types needed by tests and library users
pub use common::CommonUtils;
pub use config::ScanDefaults;
pub use rules::{Rules, match_pattern, check_for_injection_pattern};
pub use scanner::{VulnerabilityScanner, TaintAnalyzer, ScanningLogic};
pub use scanner::types::{TaintAnalysisResult};

// Re-export commonly used items from models
pub use models::{
    Finding, TaintFlow, TaintSource, TaintSink, TaintTrace, TaintSummary,
    UnifiedRule, FileTypes, Condition, Cli, LanguageInfo, FileInfo
};

pub use parser::traverse_calls_only;