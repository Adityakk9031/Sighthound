//! Core vulnerability scanning engine compatibility facade.
//!
//! The scanner implementation lives in focused sibling modules. This module keeps the
//! existing `crate::scanner::core::*` paths stable.
#![allow(clippy::too_many_arguments, clippy::large_enum_variant, clippy::needless_range_loop)]

pub use super::output::{
    print_findings_csv, print_findings_json, print_findings_text, print_summary, ProgressManager,
};
#[allow(unused_imports)]
pub(crate) use super::parser_helper::with_local_parser;
pub use super::scanning_logic::ScanningLogic;
pub use super::vulnerability_scanner::VulnerabilityScanner;
