pub mod cli;
pub mod code_type_detector;
pub mod common;
pub mod config;
pub mod language;
pub mod models;
pub mod parser;
pub mod rules;
pub mod scanner;

// Re-export the main types and functions that main.rs needs
pub use scanner::modes::run_taint_analysis_with_verbosity;
pub use scanner::{
    run_auto_detection_scan, run_explicit_scan, run_taint_analysis, FilterStats, PreFilter,
    ScanningLogic, VulnerabilityScanner,
};

// Re-export types needed by tests and library users
pub use common::CommonUtils;
pub use config::ScanDefaults;
pub use rules::{check_for_injection_pattern, match_pattern, Rules};

// Re-export code type detection
pub use code_type_detector::{CodeType, CodeTypeDetector};

// Re-export commonly used items from models
pub use models::{
    Cli, Condition, FileInfo, FileTypes, Finding, LanguageInfo, TaintFlow, TaintSink, TaintSource,
    TaintSummary, TaintTrace, UnifiedRule,
};

pub use parser::traverse_calls_only;
