use std::fs;
use std::path::Path;
use anyhow::Result;
use crate::rules::Rules;
use crate::parser::{LanguageParser, get_node_text};
use tree_sitter::Node;

#[derive(Debug, Clone)]
pub struct PreFilter {
    is_malicious_scan: bool,
    language: String,
}

impl PreFilter {
    pub fn new(rules: &Rules, language: &str) -> Self {
        Self {
            is_malicious_scan: rules.malware_detection.is_some(),
            language: language.to_string(),
        }
    }

    pub fn is_malicious_scan(&self) -> bool {
        self.is_malicious_scan
    }

    pub fn should_scan_file(&self, file_path: &str) -> bool {
        // Skip empty files
        if let Ok(metadata) = fs::metadata(file_path) {
            if metadata.len() == 0 {
                return false;
            }
        }

        // Always skip text/doc files for both modes
        if self.is_text_or_doc_file(file_path) {
            return false;
        }

        // For malicious scanning, scan everything else
        if self.is_malicious_scan {
            return true;
        }

        // For general scanning, also skip test/migration files
        !self.is_test_or_migration_file(file_path)
    }

    /// Simple text/doc file detection
    fn is_text_or_doc_file(&self, file_path: &str) -> bool {
        let path_lower = file_path.to_lowercase();
        
        // File extensions
        let skip_extensions = [".txt", ".md", ".rst", ".pdf", ".doc", ".docx", 
                              ".jpg", ".png", ".gif", ".svg", ".ico"];
        
        if skip_extensions.iter().any(|ext| path_lower.ends_with(ext)) {
            return true;
        }

        // File names
        let filename = Path::new(&path_lower)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
            
        ["readme", "license", "changelog", "authors"].iter()
            .any(|name| filename.starts_with(name))
    }

    /// Use tree-sitter to check if file is test or migration
    fn is_test_or_migration_file(&self, file_path: &str) -> bool {
        match self.extract_imports(file_path) {
            Ok(imports_text) => {
                self.has_test_patterns(&imports_text) || self.has_migration_patterns(&imports_text)
            }
            Err(_) => false, // If we can't parse, assume it's not test/migration
        }
    }

    /// Extract all import statements as a single text blob
    fn extract_imports(&self, file_path: &str) -> Result<String> {
        let source = fs::read(file_path)?;
        let mut parser = LanguageParser::new(&self.language)?;
        let tree = parser.parse(&source)?;
        
        let mut imports_text = String::new();
        self.collect_imports(&tree.root_node(), &source, &mut imports_text);
        
        Ok(imports_text.to_lowercase())
    }

    /// Recursively collect all import-like text
    fn collect_imports(&self, node: &Node, source: &[u8], imports_text: &mut String) {
        // Check if this looks like an import statement
        let node_kind = node.kind();
        if node_kind.contains("import") {
            let text = get_node_text(node, source);
            imports_text.push_str(&text);
            imports_text.push(' ');
        }

        // Recurse through children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.collect_imports(&cursor.node(), source, imports_text);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Simple pattern matching for test frameworks
    fn has_test_patterns(&self, imports_text: &str) -> bool {
        let test_patterns = [
            // Universal test indicators
            "test", "mock", "spec", "jest", "pytest", "unittest",
            "cypress", "selenium", "junit", "testng", "mocha",
            // Language specific
            "django.test", "flask.testing", "@testing-library",
            "org.junit", "org.mockito", "org.testng",
        ];
        
        test_patterns.iter().any(|pattern| imports_text.contains(pattern))
    }

    /// Simple pattern matching for migration frameworks
    fn has_migration_patterns(&self, imports_text: &str) -> bool {
        let migration_patterns = [
            "migration", "migrations", "migrate", "alembic", "flyway", "liquibase",
            "django.db.migrations", "sequelize", "knex", "typeorm",
        ];
        
        migration_patterns.iter().any(|pattern| imports_text.contains(pattern))
    }

    pub fn filter_files(&self, files: Vec<std::path::PathBuf>) -> (Vec<std::path::PathBuf>, FilterStats) {
        let mut included = 0;
        let mut filtered_out = 0;
        
        let filtered: Vec<_> = files
            .into_iter()
            .filter(|path| {
                if self.should_scan_file(&path.to_string_lossy()) {
                    included += 1;
                    true
                } else {
                    filtered_out += 1;
                    false
                }
            })
            .collect();
        
        let stats = FilterStats { included, filtered_out };
        (filtered, stats)
    }
}

#[derive(Debug, Clone)]
pub struct FilterStats {
    pub included: usize,
    pub filtered_out: usize,
}

impl FilterStats {
    pub fn total(&self) -> usize {
        self.included + self.filtered_out
    }

    pub fn filter_percentage(&self) -> f32 {
        if self.total() == 0 { 0.0 } else { 
            (self.filtered_out as f32 / self.total() as f32) * 100.0 
        }
    }
}

impl std::fmt::Display for FilterStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, 
            "📊 Pre-filter: {} included, {} filtered out ({:.1}% reduction)",
            self.included, self.filtered_out, self.filter_percentage()
        )
    }
} 