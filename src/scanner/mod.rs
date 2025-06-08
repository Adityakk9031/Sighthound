pub mod types;
pub mod core;
pub mod analyzers;
pub mod pool;
pub mod prefilter;
pub mod utils;
pub mod conditions;

pub use types::{Finding, ScanContext, FilteringStats};
pub use core::{VulnerabilityScanner, print_summary};
pub use analyzers::FileTypeAwareAnalyzer;  // Changed from RuleAnalyzer to FileTypeAwareAnalyzer
pub use pool::*;
pub use prefilter::{PreFilter, FilterStats};
pub use utils::{matches_glob_pattern, rule_applies_to_file, rule_applies_to_file_path};
pub use conditions::*;