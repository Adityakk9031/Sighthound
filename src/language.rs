use anyhow::Result;
use tree_sitter::{Language, Node};
use regex::Regex;
use once_cell::sync::Lazy;

pub trait LanguageSupport: Send + Sync {
    fn name(&self) -> &'static str;
    fn file_extension(&self) -> &'static str;
    fn tree_sitter_language(&self) -> Language;
    fn call_node_types(&self) -> &[&'static str];
    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str>;
    fn injection_patterns(&self) -> &[Regex];
    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>>;
}

pub fn get_language_support(language_name: &str) -> Result<Box<dyn LanguageSupport>> {
    match language_name.to_lowercase().as_str() {
        #[cfg(feature = "python")]
        "python" => Ok(Box::new(PythonLanguage)),
        #[cfg(feature = "java")]
        "java" => Ok(Box::new(JavaLanguage)),
        #[cfg(feature = "javascript")]
        "javascript" | "js" => Ok(Box::new(JavaScriptLanguage)),
        _ => {
            let mut supported = Vec::new();
            #[cfg(feature = "python")]
            supported.push("python");
            #[cfg(feature = "java")]
            supported.push("java");
            #[cfg(feature = "javascript")]
            supported.push("javascript");
            
            anyhow::bail!(
                "Unsupported language: {}. Supported languages: {}", 
                language_name, 
                supported.join(", ")
            )
        }
    }
}

// Python Implementation
#[cfg(feature = "python")]
pub struct PythonLanguage;

#[cfg(feature = "python")]
static PYTHON_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"%[sdfir]").unwrap(),        // String formatting
        Regex::new(r"\{.*?\}").unwrap(),         // Format strings
        Regex::new(r"\.format\(").unwrap(),      // .format() calls
        Regex::new(r#"['"][^'"]*\s\+\s"#).unwrap(), // String concatenation
        Regex::new(r#"f['""]"#).unwrap(),        // f-strings
        Regex::new(r";").unwrap(),               // Command separators
        Regex::new(r"&&").unwrap(),              // Command chaining
        Regex::new(r"\|\|").unwrap(),            // Command chaining
        Regex::new(r"\$\(").unwrap(),            // Command substitution
        Regex::new(r"`.*?`").unwrap(),           // Backtick execution
    ]
});

#[cfg(feature = "python")]
impl LanguageSupport for PythonLanguage {
    fn name(&self) -> &'static str { "python" }
    fn file_extension(&self) -> &'static str { ".py" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_python::language() }
    fn call_node_types(&self) -> &[&'static str] { &["call"] }
    
    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        if let Some(function_node) = node.child_by_field_name("function") {
            let start = function_node.start_byte();
            let end = function_node.end_byte();
            return std::str::from_utf8(&source[start..end]).ok();
        }
        None
    }
    
    fn injection_patterns(&self) -> &[Regex] { &PYTHON_INJECTION_PATTERNS }
    
    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}

// Java Implementation
#[cfg(feature = "java")]
pub struct JavaLanguage;

#[cfg(feature = "java")]
static JAVA_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"\s\+\s"#).unwrap(),        // String concatenation with +
        Regex::new(r"String\.format\(").unwrap(), // String.format() calls
        Regex::new(r"MessageFormat\.format\(").unwrap(), // MessageFormat
        Regex::new(r"PreparedStatement\.setString\(").unwrap(), // Potential SQL injection
        Regex::new(r";").unwrap(),               // Command separators
        Regex::new(r"&&").unwrap(),              // Command chaining
        Regex::new(r"\|\|").unwrap(),            // Command chaining
        Regex::new(r"\$\(").unwrap(),            // Command substitution
        Regex::new(r"`.*?`").unwrap(),           // Backtick execution
    ]
});

#[cfg(feature = "java")]
impl LanguageSupport for JavaLanguage {
    fn name(&self) -> &'static str { "java" }
    fn file_extension(&self) -> &'static str { ".java" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_java::language() }
    fn call_node_types(&self) -> &[&'static str] { 
        &["method_invocation", "object_creation_expression"]
    }
    
    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "method_invocation" => {
                if let Some(method_node) = node.child_by_field_name("name") {
                    let start = method_node.start_byte();
                    let end = method_node.end_byte();
                    return std::str::from_utf8(&source[start..end]).ok();
                }
            }
            "object_creation_expression" => {
                if let Some(type_node) = node.child_by_field_name("type") {
                    let start = type_node.start_byte();
                    let end = type_node.end_byte();
                    return std::str::from_utf8(&source[start..end]).ok();
                }
            }
            _ => {}
        }
        None
    }
    
    fn injection_patterns(&self) -> &[Regex] { &JAVA_INJECTION_PATTERNS }
    
    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}

// JavaScript Implementation
#[cfg(feature = "javascript")]
pub struct JavaScriptLanguage;

#[cfg(feature = "javascript")]
static JAVASCRIPT_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\$\{.*?\}").unwrap(),       // Template literals
        Regex::new(r#"['"][^'"]*\s\+\s"#).unwrap(), // String concatenation
        Regex::new(r"eval\(").unwrap(),          // eval() calls
        Regex::new(r"Function\(").unwrap(),      // Function constructor
        Regex::new(r"setTimeout\(").unwrap(),    // setTimeout with strings
        Regex::new(r"setInterval\(").unwrap(),   // setInterval with strings
        Regex::new(r"document\.write\(").unwrap(), // DOM manipulation
        Regex::new(r"innerHTML\s*=").unwrap(),   // innerHTML assignment
        Regex::new(r";").unwrap(),               // Command separators
        Regex::new(r"&&").unwrap(),              // Command chaining
        Regex::new(r"\|\|").unwrap(),            // Command chaining
        Regex::new(r"`.*?`").unwrap(),           // Template literals
    ]
});

#[cfg(feature = "javascript")]
impl LanguageSupport for JavaScriptLanguage {
    fn name(&self) -> &'static str { "javascript" }
    fn file_extension(&self) -> &'static str { ".js" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_javascript::language() }
    fn call_node_types(&self) -> &[&'static str] { 
        &["call_expression", "new_expression"]
    }
    
    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "call_expression" => {
                if let Some(function_node) = node.child_by_field_name("function") {
                    let start = function_node.start_byte();
                    let end = function_node.end_byte();
                    return std::str::from_utf8(&source[start..end]).ok();
                }
            }
            "new_expression" => {
                if let Some(constructor_node) = node.child_by_field_name("constructor") {
                    let start = constructor_node.start_byte();
                    let end = constructor_node.end_byte();
                    return std::str::from_utf8(&source[start..end]).ok();
                }
            }
            _ => {}
        }
        None
    }
    
    fn injection_patterns(&self) -> &[Regex] { &JAVASCRIPT_INJECTION_PATTERNS }
    
    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
} 