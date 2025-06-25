pub mod types;
pub mod core;
pub mod pool;
pub mod prefilter;
pub mod utils;
pub mod conditions;
pub mod shared;
pub mod taint;

pub use types::{Finding, FilteringStats};
pub use core::{VulnerabilityScanner, print_summary};
pub use pool::*;
pub use prefilter::{PreFilter, FilterStats};
pub use utils::{matches_glob_pattern, rule_applies_to_file, rule_applies_to_file_path};
pub use conditions::*;
pub use shared::ScanningLogic;
pub use taint::{TaintAnalyzer, TaintAnalysisResult, TaintFlow, TaintSource, TaintSink, TaintTrace, TraceType, TaintSummary};