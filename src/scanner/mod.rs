pub mod core;
pub mod conditions;
pub mod data_flow;
pub mod modes;
pub mod prefilter;
pub mod taint;
pub mod utils;

pub use core::{VulnerabilityScanner, ScanningLogic, ProgressManager, print_findings_json, print_findings_csv, print_findings_text, print_summary};
pub use crate::models::{Finding, SourceInfo, SinkInfo, TraceStep};
pub use prefilter::{PreFilter, FilterStats};
pub use utils::{matches_glob_pattern, rule_applies_to_file, rule_applies_to_file_path, detect_language_from_path, discover_files_by_language_parallel, discover_files_by_language_sequential};
pub use conditions::*;
pub use taint::{TaintAnalyzer, TaintAnalysisResult, merge_taint_results};
pub use crate::models::{TaintFlow, TaintSource, TaintSink, TaintTrace, TraceType, TaintSummary};
pub use modes::{run_explicit_scan, run_auto_detection_scan, run_taint_analysis};