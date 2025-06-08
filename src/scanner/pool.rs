use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use anyhow::Result;
use crate::parser::LanguageParser;

/// A thread-safe pool of pre-allocated parsers for high-performance parsing
pub struct ParserPool {
    parsers: crossbeam::queue::SegQueue<LanguageParser>,
    language_name: String,
    pool_size: usize,
    created_count: AtomicUsize,
    max_parsers: usize,
}

impl ParserPool {
    /// Create a new parser pool with the specified initial size
    pub fn new(language_name: &str, initial_size: usize) -> Result<Arc<Self>> {
        let pool = Arc::new(Self {
            parsers: crossbeam::queue::SegQueue::new(),
            language_name: language_name.to_string(),
            pool_size: initial_size,
            created_count: AtomicUsize::new(0),
            max_parsers: initial_size * 2, // Allow pool to grow up to 2x initial size
        });
        
        // Pre-populate the pool with parsers
        for _ in 0..initial_size {
            let parser = LanguageParser::new(language_name)?;
            pool.parsers.push(parser);
            pool.created_count.fetch_add(1, Ordering::Relaxed);
        }
        
        Ok(pool)
    }
    
    /// Get a parser from the pool. Creates a new one if pool is empty.
    pub fn get_parser(&self) -> Result<LanguageParser> {
        // Fast path: try to get from pool
        if let Some(parser) = self.parsers.pop() {
            return Ok(parser);
        }
        
        // Slow path: create new parser if we haven't hit the limit
        let current_count = self.created_count.load(Ordering::Relaxed);
        if current_count < self.max_parsers {
            match LanguageParser::new(&self.language_name) {
                Ok(parser) => {
                    self.created_count.fetch_add(1, Ordering::Relaxed);
                    return Ok(parser);
                }
                Err(e) => return Err(e),
            }
        }
        
        // If we've hit the limit, wait a bit and try the pool again
        // This handles temporary pool exhaustion gracefully
        std::thread::yield_now();
        if let Some(parser) = self.parsers.pop() {
            return Ok(parser);
        }
        
        // Last resort: create a temporary parser (will not be returned to pool)
        LanguageParser::new(&self.language_name)
    }
    
    /// Return a parser to the pool for reuse
    pub fn return_parser(&self, parser: LanguageParser) {
        // Only return to pool if we haven't exceeded the maximum size
        if self.parsers.len() < self.pool_size {
            self.parsers.push(parser);
        }
        // Otherwise, let the parser be dropped to free memory
    }
    
    /// Get pool statistics for monitoring
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            available: self.parsers.len(),
            total_created: self.created_count.load(Ordering::Relaxed),
            pool_size: self.pool_size,
            max_parsers: self.max_parsers,
        }
    }
}

/// Statistics about parser pool usage
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub available: usize,
    pub total_created: usize,
    pub pool_size: usize,
    pub max_parsers: usize,
}

impl std::fmt::Display for PoolStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Pool: {}/{} available, {} total created (max: {})",
            self.available, self.pool_size, self.total_created, self.max_parsers
        )
    }
}

/// RAII wrapper for automatically returning parser to pool
pub struct PooledParser {
    parser: Option<LanguageParser>,
    pool: Arc<ParserPool>,
}

impl PooledParser {
    pub fn new(pool: Arc<ParserPool>) -> Result<Self> {
        let parser = pool.get_parser()?;
        Ok(Self {
            parser: Some(parser),
            pool,
        })
    }
    
    /// Get mutable reference to the parser
    pub fn parser_mut(&mut self) -> &mut LanguageParser {
        self.parser.as_mut().expect("Parser should be available")
    }
    
    /// Get immutable reference to the parser
    pub fn parser(&self) -> &LanguageParser {
        self.parser.as_ref().expect("Parser should be available")
    }
}

impl Drop for PooledParser {
    fn drop(&mut self) {
        if let Some(parser) = self.parser.take() {
            self.pool.return_parser(parser);
        }
    }
} 