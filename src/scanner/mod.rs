pub mod core;
pub mod modes;
pub mod utils;
pub mod conditions;
pub mod prefilter;
pub mod taint;

pub use core::{VulnerabilityScanner, ScanningLogic};
pub use crate::models::Finding;
pub use modes::{run_explicit_scan, run_auto_detection_scan, run_taint_analysis};
pub use prefilter::{PreFilter, FilterStats};

pub use taint::{TaintAnalyzer, TaintAnalysisResult, merge_taint_results};