pub mod types;
pub mod core;
pub mod pool;
pub mod prefilter;
pub mod utils;
pub mod conditions;
pub mod shared;
pub mod taint;
pub mod modes;

pub use types::{Finding, FilteringStats};
pub use core::{VulnerabilityScanner, print_summary, ProgressManager, print_findings_json, print_findings_csv, print_findings_text};
pub use pool::*;
pub use prefilter::{PreFilter, FilterStats};
pub use utils::{matches_glob_pattern, rule_applies_to_file, rule_applies_to_file_path, detect_language_from_path, discover_files_by_language_parallel, discover_files_by_language_sequential};
pub use conditions::*;
pub use shared::ScanningLogic;
pub use taint::{TaintAnalyzer, TaintAnalysisResult, TaintFlow, TaintSource, TaintSink, TaintTrace, TraceType, TaintSummary, print_taint_analysis_json, print_taint_analysis_text, merge_taint_results};
pub use modes::{run_explicit_scan, run_auto_detection_scan, run_taint_analysis};