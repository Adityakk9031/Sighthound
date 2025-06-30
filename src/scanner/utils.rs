use crate::rules::FileTypes;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use anyhow::Result;
use walkdir::WalkDir;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use crate::skip::SKIP_DIRS;
use tree_sitter::Node;
use crate::common::CommonUtils;
use crate::parser::get_node_text;

/// Check if a file path matches a glob pattern (delegates to common utils)
pub fn matches_glob_pattern(pattern: &str, file_path: &str) -> bool {
    crate::common::CommonUtils::file_matches_pattern(pattern, file_path)
}

/// Check if a rule applies to a given file path based on file type constraints
pub fn rule_applies_to_file(file_types: Option<&FileTypes>, file_path: &str) -> bool {
    // If no file types specified, rule applies to all files
    let Some(file_types) = file_types else {
        return true;
    };

    // Check include patterns first
    if let Some(include_patterns) = &file_types.include_patterns {
        let mut matches_include = false;
        for pattern in include_patterns {
            if matches_glob_pattern(pattern, file_path) {
                matches_include = true;
                break;
            }
        }
        if !matches_include {
            return false;
        }
    }

    // Check exclude patterns
    if let Some(exclude_patterns) = &file_types.exclude_patterns {
        for pattern in exclude_patterns {
            if matches_glob_pattern(pattern, file_path) {
                return false;
            }
        }
    }

    // Check extensions
    if let Some(extensions) = &file_types.extensions {
        if let Some(file_extension) = Path::new(file_path).extension() {
            if let Some(ext_str) = file_extension.to_str() {
                let ext_with_dot = format!(".{}", ext_str);
                if !extensions.contains(&ext_str.to_string()) && !extensions.contains(&ext_with_dot) {
                    return false;
                }
            }
        } else {
            // File has no extension, but rule requires specific extensions
            return false;
        }
    }

    true
}

/// Helper function to check if file types match (for Path-based version)
pub fn rule_applies_to_file_path(file_types: Option<&FileTypes>, file_path: &Path) -> bool {
    rule_applies_to_file(file_types, &file_path.to_string_lossy())
}

/// Detect programming language from file path
pub fn detect_language_from_path(file_path: &Path) -> Option<&'static str> {
    match file_path.extension()?.to_str()? {
        "py" => Some("python"),
        "java" => Some("java"),
        "js" | "mjs" => Some("javascript"),
        "tsx" => Some("tsx"),
        "html" => {
            let path_str = file_path.to_string_lossy().to_lowercase();
            if path_str.contains("template") || path_str.contains("django") {
                Some("html")
            } else {
                Some("html")
            }
        },
        _ => None,
    }
}

/// Discover files by language with configurable parallelism
pub fn discover_files_by_language(root_dir: &str, parallel: bool) -> Result<HashMap<String, Vec<PathBuf>>> {
    let estimated_languages = crate::config::ScanDefaults::ESTIMATED_LANGUAGES;
    
    if parallel {
        discover_files_parallel(root_dir, estimated_languages)
    } else {
        discover_files_sequential(root_dir, estimated_languages)
    }
}

/// Internal parallel file discovery implementation
fn discover_files_parallel(root_dir: &str, estimated_languages: usize) -> Result<HashMap<String, Vec<PathBuf>>> {
    let all_paths: Vec<PathBuf> = WalkDir::new(root_dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if e.file_type().is_dir() {
                if let Some(name) = e.file_name().to_str() {
                    return !SKIP_DIRS.contains(&name);
                }
            }
            true
        })
        .par_bridge()
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                if e.path().is_file() {
                    Some(e.path().to_path_buf())
                } else { None }
            })
        })
        .collect();
    
    let estimated_files_per_lang = if all_paths.is_empty() { 
        crate::config::ScanDefaults::ESTIMATED_FILES_PER_LANG 
    } else { 
        (all_paths.len() / estimated_languages).max(crate::config::ScanDefaults::ESTIMATED_FILES_PER_LANG) 
    };
    
    println!("📂 Discovered {} files total, estimating {} files per language", 
             all_paths.len(), estimated_files_per_lang);
    
    let files_by_language = Arc::new(Mutex::new(
        HashMap::<String, Vec<PathBuf>>::with_capacity(estimated_languages)
    ));
    
    all_paths.par_iter().for_each(|path| {
        if let Some(language) = detect_language_from_path(path) {
            let mut map = files_by_language.lock().unwrap();
            map.entry(language.to_string())
                .or_insert_with(|| Vec::with_capacity(estimated_files_per_lang))
                .push(path.clone());
        }
    });
    
    Arc::try_unwrap(files_by_language)
        .map_err(|_| anyhow::anyhow!("Failed to unwrap shared file map"))?
        .into_inner()
        .map_err(|e| anyhow::anyhow!("Failed to acquire mutex: {:?}", e))
}

/// Internal sequential file discovery implementation
fn discover_files_sequential(root_dir: &str, estimated_languages: usize) -> Result<HashMap<String, Vec<PathBuf>>> {
    let mut files_by_language = HashMap::with_capacity(estimated_languages);
    
    for entry in WalkDir::new(root_dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if e.file_type().is_dir() {
                if let Some(name) = e.file_name().to_str() {
                    return !SKIP_DIRS.contains(&name);
                }
            }
            true
        })
        .filter_map(|e| e.ok())
    {
        if entry.path().is_file() {
            if let Some(language) = detect_language_from_path(entry.path()) {
                files_by_language
                    .entry(language.to_string())
                    .or_insert_with(|| Vec::with_capacity(crate::config::ScanDefaults::ESTIMATED_FILES_PER_LANG))
                    .push(entry.path().to_path_buf());
            }
        }
    }
    
    Ok(files_by_language)
}

/// Parallel file discovery (replaces legacy wrapper)
pub fn discover_files_by_language_parallel(root_dir: &str) -> Result<HashMap<String, Vec<PathBuf>>> {
    discover_files_by_language(root_dir, true)
}

/// Sequential file discovery (replaces legacy wrapper)
pub fn discover_files_by_language_sequential(root_dir: &str) -> Result<HashMap<String, Vec<PathBuf>>> {
    discover_files_by_language(root_dir, false)
}

// =========================================================================
// AST UTILITIES (consolidated from ast_utils.rs)
// =========================================================================

/// AST utilities focused on semantic analysis and classification
pub struct AstUtils;

impl AstUtils {
    /// Determine if a code pattern represents a source, sink, or neither
    pub fn classify_code_pattern(code: &str, pattern: &str) -> CodePatternType {
        // Context-aware classification
        if Self::is_configuration_pattern(code) {
            return CodePatternType::Configuration;
        }
        
        if Self::is_user_input_pattern(code, pattern) {
            return CodePatternType::UserInput;
        }
        
        if Self::is_dangerous_sink_pattern(code, pattern) {
            return CodePatternType::DangerousSink;
        }
        
        CodePatternType::Neutral
    }
    
    /// Check if code represents configuration (safe) - FIXED: Much more specific
    fn is_configuration_pattern(code: &str) -> bool {
        // SPECIFIC configuration patterns only - not broad keyword matching
        let specific_config_patterns = [
            ".setdefault(",           // os.environ.setdefault()
            "load_config(",           // config loading
            "configure(",             // configure() calls
            "settings.",              // settings.SOMETHING
            "_config.",               // some_config.something
        ];
        
        // Only match if it's clearly a configuration operation, not just containing keywords
        specific_config_patterns.iter().any(|&pattern| code.contains(pattern)) ||
        // Special case: setdefault is always configuration
        (code.contains("setdefault") && code.contains("("))
    }
    
    /// Check if code represents user input (source)
    fn is_user_input_pattern(code: &str, pattern: &str) -> bool {
        // Only consider user input if it's actually getting user data
        let user_input_patterns = [
            "input(",
            "raw_input(",
            "request.args",
            "request.form",
            "request.json",
            "sys.argv",
        ];
        
        user_input_patterns.iter().any(|&p| code.contains(p)) ||
        (pattern.contains("environ") && Self::is_environment_read(code))
    }
    
    /// Check if environment access is reading (source) vs setting (config)
    pub fn is_environment_read(code: &str) -> bool {
        code.contains("get(") || code.contains("[]") // os.environ.get() or os.environ['key']
    }
    
    /// Check if code represents dangerous sink
    fn is_dangerous_sink_pattern(_code: &str, pattern: &str) -> bool {
        let dangerous_sinks = [
            "os.system",
            "subprocess.call",
            "subprocess.run",
            "eval(",
            "exec(",
            "open(",
        ];
        
        dangerous_sinks.iter().any(|&sink| pattern.contains(sink))
    }

    // =========================================================================
    // AST NODE OPERATIONS
    // =========================================================================

    /// Get function context from AST node
    pub fn get_function_context(node: &Node, source: &[u8]) -> String {
        let mut current = *node;
        
        // Look for containing function
        loop {
            if Self::is_function_node(&current) {
                // Try to get function name
                if let Some(name) = Self::extract_function_name(&current, source) {
                    return name;
                }
            }
            
            if let Some(parent) = current.parent() {
                current = parent;
            } else {
                break;
            }
        }
        
        "global".to_string()
    }

    /// Check if node is a function definition
    pub fn is_function_node(node: &Node) -> bool {
        matches!(node.kind(), 
            "function_definition" | "function_declaration" | "method_definition" |
            "arrow_function" | "function_expression" | "generator_function" |
            "async_function" | "constructor_definition"
        )
    }

    /// Extract function name from function node
    pub fn extract_function_name(node: &Node, source: &[u8]) -> Option<String> {
        // Try field-based extraction first
        if let Some(name_node) = node.child_by_field_name("name") {
            return Some(get_node_text(&name_node, source));
        }
        
        // Try child-based extraction
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if cursor.node().kind() == "identifier" {
                    return Some(get_node_text(&cursor.node(), source));
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        None
    }

    // =========================================================================
    // SECURITY-SPECIFIC ANALYSIS
    // =========================================================================

    /// Domain-specific sanitization pattern checking
    pub fn check_for_sanitization(code: &str, language: &str) -> bool {
        match language {
            "javascript" | "typescript" => Self::check_javascript_sanitization(code),
            "python" => Self::check_python_sanitization(code),
            "java" => Self::check_java_sanitization(code),
            _ => Self::check_generic_sanitization(code),
        }
    }

    fn check_javascript_sanitization(code: &str) -> bool {
        let js_sanitizers = [
            "DOMPurify.sanitize", "sanitize(", ".textContent", ".innerText",
            "encodeURIComponent", "encodeURI", "escape(", "validator.escape", "xss(",
        ];
        js_sanitizers.iter().any(|pattern| code.contains(pattern))
    }

    fn check_python_sanitization(code: &str) -> bool {
        let py_sanitizers = [
            "html.escape", "cgi.escape", "urllib.parse.quote", "bleach.clean",
            "markupsafe.escape", "jinja2.escape", "django.utils.html.escape",
        ];
        py_sanitizers.iter().any(|pattern| code.contains(pattern))
    }

    fn check_java_sanitization(code: &str) -> bool {
        let java_sanitizers = [
            "StringEscapeUtils.escape", "ESAPI.encoder", "URLEncoder.encode",
            "StringUtils.escape", ".encode(", "sanitize(",
        ];
        java_sanitizers.iter().any(|pattern| code.contains(pattern))
    }

    fn check_generic_sanitization(code: &str) -> bool {
        let generic_sanitizers = [
            "sanitize(", "escape(", "encode(", "clean(", "validate(",
            "filter(", "purify(", "safe(",
        ];
        generic_sanitizers.iter().any(|pattern| code.contains(pattern))
    }
    
    /// Extract variables from expression with semantic understanding  
    pub fn extract_semantic_variables(node: &Node, source: &[u8]) -> Vec<SemanticVariable> {
        let node_text = get_node_text(node, source);
        let mut variables = Vec::new();
        
        match node.kind() {
            "assignment" | "assignment_expression" => {
                if let Some(target) = CommonUtils::extract_variable_from_assignment(&node_text, false) {
                    variables.push(SemanticVariable {
                        name: target,
                        var_type: VariableType::AssignmentTarget,
                        context: node_text.clone(),
                    });
                }
                
                // Extract source variables from right side
                if let Some(eq_pos) = node_text.find('=') {
                    let right_side = node_text[eq_pos + 1..].trim();
                    let source_vars = CommonUtils::extract_variables_from_expression(right_side);
                    for var in source_vars {
                        variables.push(SemanticVariable {
                            name: var,
                            var_type: VariableType::Source,
                            context: right_side.to_string(),
                        });
                    }
                }
            }
            "call" => {
                // Extract function call arguments
                if let Some(args) = CommonUtils::extract_function_arguments(&node_text) {
                    for arg in args {
                        if CommonUtils::is_valid_variable_name(&arg) {
                            variables.push(SemanticVariable {
                                name: arg,
                                var_type: VariableType::FunctionArgument,
                                context: node_text.clone(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        
        variables
    }
}

#[derive(Debug, Clone)]
pub enum CodePatternType {
    UserInput,
    DangerousSink,
    Configuration,
    Neutral,
}

#[derive(Debug, Clone)]
pub struct SemanticVariable {
    pub name: String,
    pub var_type: VariableType,
    pub context: String,
}

#[derive(Debug, Clone)]
pub enum VariableType {
    AssignmentTarget,
    Source,
    FunctionArgument,
} 