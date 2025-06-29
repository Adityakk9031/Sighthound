pub mod ast_utils;
pub mod conditions;
pub mod core;
pub mod data_flow;
pub mod modes;
pub mod prefilter;
pub mod shared;
pub mod taint;
pub mod types;
pub mod utils;

pub use types::Finding;
pub use core::{VulnerabilityScanner, print_summary, ProgressManager, print_findings_json, print_findings_csv, print_findings_text};
pub use prefilter::{PreFilter, FilterStats};
pub use utils::{matches_glob_pattern, rule_applies_to_file, rule_applies_to_file_path, detect_language_from_path, discover_files_by_language_parallel, discover_files_by_language_sequential};
pub use conditions::*;
pub use shared::ScanningLogic;
pub use taint::{TaintAnalyzer, TaintAnalysisResult, TaintFlow, TaintSource, TaintSink, TaintTrace, TraceType, TaintSummary, merge_taint_results};
pub use modes::{run_explicit_scan, run_auto_detection_scan, run_taint_analysis};