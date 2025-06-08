pub mod types;
pub mod core;
pub mod analyzers;
pub mod pool;
pub mod prefilter;

pub use types::{Finding, ScanContext, FilteringStats};
pub use core::{VulnerabilityScanner, print_summary};
pub use analyzers::FileTypeAwareAnalyzer;  // Changed from RuleAnalyzer to FileTypeAwareAnalyzer
pub use pool::*;
pub use prefilter::{PreFilter, FilterStats};