use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub function: String,
    pub finding_type: String,
    pub code: String,
}

#[derive(Debug, Clone)]
pub struct ScanContext {
    pub filepath: String,
    pub source: Vec<u8>,
    pub tree: tree_sitter::Tree,
}

impl ScanContext {
    pub fn new(filepath: String, source: Vec<u8>, tree: tree_sitter::Tree) -> Self {
        Self { filepath, source, tree }
    }
}

// NEW: File type filtering structures
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub extension: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct FilteringStats {
    pub total_rules_checked: usize,
    pub applicable_rules_found: usize,
    pub files_processed: usize,
    pub cache_hits: usize,
    pub extension_filters_applied: usize,
    pub path_filters_applied: usize,
    pub size_filters_applied: usize,
}

impl FilteringStats {
    pub fn new() -> Self {
        Self {
            total_rules_checked: 0,
            applicable_rules_found: 0,
            files_processed: 0,
            cache_hits: 0,
            extension_filters_applied: 0,
            path_filters_applied: 0,
            size_filters_applied: 0,
        }
    }

    pub fn efficiency_ratio(&self) -> f64 {
        if self.total_rules_checked == 0 {
            return 0.0;
        }
        (self.total_rules_checked - self.applicable_rules_found) as f64 / self.total_rules_checked as f64
    }

    pub fn print_summary(&self) {
        println!("\n📊 File-Type Filtering Statistics:");
        println!("  Files processed: {}", self.files_processed);
        println!("  Total rules available: {}", self.total_rules_checked);
        println!("  Rules applied after filtering: {}", self.applicable_rules_found);
        println!("  Filtering efficiency: {:.1}% rules skipped", self.efficiency_ratio() * 100.0);
        println!("  Cache hits: {}", self.cache_hits);
        println!("  Extension filters applied: {}", self.extension_filters_applied);
        println!("  Path filters applied: {}", self.path_filters_applied);
        println!("  Size filters applied: {}", self.size_filters_applied);
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileTypeFilter {
    /// File extensions this rule applies to (e.g., [".py", ".js"])
    #[serde(default)]
    pub extensions: Vec<String>,
    
    /// Glob patterns for file paths (optional)
    pub path_patterns: Option<Vec<String>>,
    
    /// Exclude certain file patterns (optional)
    pub exclude_patterns: Option<Vec<String>>,
    
    /// Maximum file size to process (in bytes, optional)
    pub max_file_size: Option<u64>,
}

impl Default for FileTypeFilter {
    fn default() -> Self {
        Self {
            extensions: Vec::new(),
            path_patterns: None,
            exclude_patterns: None,
            max_file_size: None,
        }
    }
}