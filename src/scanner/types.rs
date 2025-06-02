use serde::Serialize;
use std::path::PathBuf;
use tree_sitter::Tree;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub function: String,
    pub finding_type: String,
    pub code: String,
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
    pub extension: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanContext {
    pub language_name: String,
    pub rules_file: String,
    pub parallel: bool,
    pub max_threads: Option<usize>,
    pub filepath: String,
    pub source: Vec<u8>,
    pub tree: Tree,
}

#[derive(Debug, Clone, Default)]
pub struct FilteringStats {
    pub total_files: usize,
    pub processed_files: usize,
    pub filtered_out_files: usize,
    pub rules_applied: usize,
    pub filtered_out_rules: usize,
    pub files_processed: usize,
    pub total_rules_checked: usize,
    pub applicable_rules_found: usize,
    pub extension_filters_applied: usize,
    pub cache_hits: usize,
}

impl FilteringStats {
    pub fn new() -> Self {
        Self::default()
    }
}