/// Centralized configuration constants for the scanner
pub struct ScanDefaults;

impl ScanDefaults {
    /// Chunk size for parallel file processing (tuned for disk I/O)
    pub const CHUNK_SIZE: usize = 64;
    
    /// Progress update interval in milliseconds
    pub const PROGRESS_INTERVAL_MS: u64 = 100;
    
    /// Estimated files per language for capacity planning
    pub const ESTIMATED_FILES_PER_LANG: usize = 50;
    
    /// Maximum AST traversal depth to prevent infinite recursion
    pub const MAX_AST_DEPTH: usize = 20;
    
    /// Maximum file size to process (10MB)
    pub const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;
    
    /// Estimated languages for HashMap capacity
    pub const ESTIMATED_LANGUAGES: usize = 6;
} 