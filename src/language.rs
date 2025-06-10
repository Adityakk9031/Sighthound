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
        #[cfg(feature = "tsx")]
        "tsx" | "typescript-jsx" => Ok(Box::new(TSXLanguage)),
        #[cfg(feature = "html")]
        "html" => Ok(Box::new(HTMLLanguage)),
        #[cfg(feature = "django")]
        "django" | "django-html" => Ok(Box::new(DjangoTemplateLanguage)),
        _ => {
            let mut supported = Vec::new();
            #[cfg(feature = "python")]
            supported.push("python");
            #[cfg(feature = "java")]
            supported.push("java");
            #[cfg(feature = "javascript")]
            supported.push("javascript");
            #[cfg(feature = "tsx")]
            supported.push("tsx");
            #[cfg(feature = "html")]
            supported.push("html");
            #[cfg(feature = "django")]
            supported.push("django");
            
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
    fn tree_sitter_language(&self) -> Language { tree_sitter_python::LANGUAGE.into() }
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
    fn tree_sitter_language(&self) -> Language { tree_sitter_java::LANGUAGE.into() }
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
    fn tree_sitter_language(&self) -> Language { tree_sitter_javascript::LANGUAGE.into() }
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

// TSX Implementation
#[cfg(feature = "tsx")]
pub struct TSXLanguage;

#[cfg(feature = "tsx")]
static TSX_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // React-specific XSS patterns
        Regex::new(r#"dangerouslySetInnerHTML\s*=\s*\{\{.*?\}\}"#).unwrap(),
        // JSX expressions with user input
        Regex::new(r"\{[^}]*\$\{.*?\}[^}]*\}").unwrap(),
        // Event handler injection
        Regex::new(r#"on[A-Z]\w*\s*=\s*\{[^}]*eval\("#).unwrap(),
        // Template literal injection
        Regex::new(r"\$\{[^}]*\}").unwrap(),
        // Dynamic imports
        Regex::new(r"import\s*\([^)]*\)").unwrap(),
        // JavaScript injection patterns (inherit from JS)
        Regex::new(r"eval\(").unwrap(),
        Regex::new(r"Function\(").unwrap(),
        Regex::new(r"innerHTML\s*=").unwrap(),
        // JSX attribute injection
        Regex::new(r#"on\w+\s*=\s*\{.*?\}"#).unwrap(),
        // React refs with dangerous operations
        Regex::new(r"ref\s*=\s*\{.*?\.innerHTML").unwrap(),
    ]
});

#[cfg(feature = "tsx")]
impl LanguageSupport for TSXLanguage {
    fn name(&self) -> &'static str { "tsx" }
    fn file_extension(&self) -> &'static str { ".tsx" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_typescript::LANGUAGE_TSX.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["call_expression", "new_expression", "jsx_expression", "jsx_attribute"]
    }
    
    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "jsx_attribute" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let start = name_node.start_byte();
                    let end = name_node.end_byte();
                    return std::str::from_utf8(&source[start..end]).ok();
                }
            }
            "call_expression" => {
                if let Some(function_node) = node.child_by_field_name("function") {
                    let start = function_node.start_byte();
                    let end = function_node.end_byte();
                    return std::str::from_utf8(&source[start..end]).ok();
                }
            }
            "jsx_expression" => {
                // Handle JSX expressions
                let start = node.start_byte();
                let end = node.end_byte();
                return std::str::from_utf8(&source[start..end]).ok();
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
    
    fn injection_patterns(&self) -> &[Regex] { &TSX_INJECTION_PATTERNS }
    
    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
            .or_else(|| node.child_by_field_name("value"))
    }
}

// HTML Implementation
#[cfg(feature = "html")]
pub struct HTMLLanguage;

#[cfg(feature = "html")]
static HTML_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Inline event handlers
        Regex::new(r#"on\w+\s*=\s*["'][^"']*["']"#).unwrap(),
        // JavaScript URLs
        Regex::new(r#"href\s*=\s*["']javascript:[^"']*["']"#).unwrap(),
        // Script tags with inline content
        Regex::new(r"<script[^>]*>[^<]*</script>").unwrap(),
        // Dangerous attributes
        Regex::new(r#"srcdoc\s*=\s*["'][^"']*["']"#).unwrap(),
        // Data URLs with JavaScript
        Regex::new(r#"data:text/html[^"']*["']"#).unwrap(),
        // Form action with javascript
        Regex::new(r#"action\s*=\s*["']javascript:[^"']*["']"#).unwrap(),
        // Meta refresh with javascript
        Regex::new(r#"content\s*=\s*["'][^"']*url=javascript:[^"']*["']"#).unwrap(),
    ]
});

#[cfg(feature = "html")]
impl LanguageSupport for HTMLLanguage {
    fn name(&self) -> &'static str { "html" }
    fn file_extension(&self) -> &'static str { ".html" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_html::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["attribute", "start_tag", "script_element", "element", "text"]
    }
    
    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "attribute" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let start = name_node.start_byte();
                    let end = name_node.end_byte();
                    return std::str::from_utf8(&source[start..end]).ok();
                }
                if let Some(first_child) = node.child(0) {
                    let start = first_child.start_byte();
                    let end = first_child.end_byte();
                    return std::str::from_utf8(&source[start..end]).ok();
                }
            }
            "start_tag" | "element" => {
                // Check if this is a form tag
                let start = node.start_byte();
                let end = node.end_byte();
                let text = std::str::from_utf8(&source[start..end]).ok()?;
                if text.contains("<form") {
                    return Some("<form");
                }
                
                // Look for attributes in the element
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "attribute" {
                            if let Some(attr_name) = self.get_function_name(&child, source) {
                                return Some(attr_name);
                            }
                        }
                    }
                }
            }
            "script_element" => {
                return Some("script");
            }
            "text" => {
                let start = node.start_byte();
                let end = node.end_byte();
                let text = std::str::from_utf8(&source[start..end]).ok()?;
                if text.contains("javascript:") || text.contains("eval(") {
                    return Some("text_content");
                }
            }
            _ => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "attribute" {
                            if let Some(attr_name) = self.get_function_name(&child, source) {
                                return Some(attr_name);
                            }
                        }
                    }
                }
            }
        }
        None
    }
    
    fn injection_patterns(&self) -> &[Regex] { &HTML_INJECTION_PATTERNS }
    
    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        // For HTML attributes, we need to find the value part
        if node.kind() == "attribute" {
            // Method 1: Try field-based access first
            if let Some(value_node) = node.child_by_field_name("value") {
                return Some(value_node);
            }
            
            // Method 2: Look for specific value node types
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    match child.kind() {
                        "attribute_value" | "quoted_attribute_value" | "string" => {
                            return Some(child);
                        }
                        _ => continue,
                    }
                }
            }
            
            // Method 3: Find the last child (often the value in tree-sitter HTML)
            if node.child_count() > 1 {
                return node.child(node.child_count() - 1);
            }
        }
        
        // For other node types, try standard field access
        node.child_by_field_name("value")
    }
}

// Django Template Implementation
#[cfg(feature = "django")]
pub struct DjangoTemplateLanguage;

#[cfg(feature = "django")]
static DJANGO_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Django template variables marked as safe
        Regex::new(r"\{\{\s*[^}]*\|safe\s*\}\}").unwrap(),
        // Django template variables in JavaScript context
        Regex::new(r"<script[^>]*>[^<]*\{\{[^}]*\}\}[^<]*</script>").unwrap(),
        // Event handlers with Django variables
        Regex::new(r#"on\w+\s*=\s*["'][^"']*\{\{[^}]*\}\}[^"']*["']"#).unwrap(),
        // Django template tags that could be dangerous
        Regex::new(r"\{\%\s*autoescape\s+off\s*\%\}").unwrap(),
        // Django template includes without proper escaping
        Regex::new(r"\{\%\s*include\s+[^%]*\%\}").unwrap(),
        // Django mark_safe filter
        Regex::new(r"\{\{\s*[^}]*\|mark_safe\s*\}\}").unwrap(),
        // Django template variables in href attributes
        Regex::new(r#"href\s*=\s*["'][^"']*\{\{[^}]*\}\}[^"']*["']"#).unwrap(),
        // Django template variables in src attributes
        Regex::new(r#"src\s*=\s*["'][^"']*\{\{[^}]*\}\}[^"']*["']"#).unwrap(),
    ]
});

#[cfg(feature = "django")]
impl LanguageSupport for DjangoTemplateLanguage {
    fn name(&self) -> &'static str { "django" }
    fn file_extension(&self) -> &'static str { ".html" }  // Django templates use .html
    fn tree_sitter_language(&self) -> Language { tree_sitter_html::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["attribute", "text", "script_element"]
    }
    
    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "text" => {
                let start = node.start_byte();
                let end = node.end_byte();
                let text = std::str::from_utf8(&source[start..end]).ok()?;
                
                // Check for specific Django template patterns
                if text.contains("|safe") {
                    return Some("|safe");
                }
                if text.contains("|mark_safe") {
                    return Some("|mark_safe");
                }
                if text.contains("{% autoescape off %}") || text.contains("{%autoescape off%}") {
                    return Some("{% autoescape off %}");
                }
                if text.contains("{{") && text.contains("}}") {
                    return Some("{{");
                }
                if text.contains("{% include") || text.contains("{%include") {
                    return Some("{% include");
                }
                if text.contains("{% extends") || text.contains("{%extends") {
                    return Some("{% extends");
                }
                if text.contains("{% ssi") || text.contains("{%ssi") {
                    return Some("{% ssi");
                }
                if text.contains("{% url") || text.contains("{%url") {
                    return Some("{% url");
                }
                if text.contains("{% static") || text.contains("{%static") {
                    return Some("{% static");
                }
                if text.contains("|raw") {
                    return Some("|raw");
                }
                if text.contains("<!--") {
                    return Some("<!--");
                }
                if text.contains("{#") && text.contains("#}") {
                    return Some("{#");
                }
                // Generic Django template detection
                if text.contains("{{") || text.contains("{%") {
                    return Some("django_template");
                }
            }
            "attribute" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let start = name_node.start_byte();
                    let end = name_node.end_byte();
                    let attr_name = std::str::from_utf8(&source[start..end]).ok()?;
                    
                    // Check for event handlers
                    if attr_name.starts_with("on") {
                        return Some(attr_name);
                    }
                    
                    return Some(attr_name);
                }
            }
            "script_element" => {
                return Some("script");
            }
            "start_tag" | "element" => {
                // Check if this is a form tag
                let start = node.start_byte();
                let end = node.end_byte();
                let text = std::str::from_utf8(&source[start..end]).ok()?;
                if text.contains("<form") {
                    return Some("<form");
                }
                
                // Look for attributes in the element
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "attribute" {
                            if let Some(attr_name) = self.get_function_name(&child, source) {
                                return Some(attr_name);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }
    
    fn injection_patterns(&self) -> &[Regex] { &DJANGO_INJECTION_PATTERNS }
    
    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        // For Django templates, we need to extract content from text nodes and attribute values
        match node.kind() {
            "text" => {
                // Return the text node itself so conditions can check its content
                Some(*node)
            }
            "attribute" => {
                // Look for attribute value
                if let Some(value_node) = node.child_by_field_name("value") {
                    return Some(value_node);
                }
                // Fallback to searching for value nodes
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        match child.kind() {
                            "attribute_value" | "quoted_attribute_value" | "string" => {
                                return Some(child);
                            }
                            _ => continue,
                        }
                    }
                }
                None
            }
            "start_tag" | "element" => {
                // For form elements, return the element itself for content checking
                Some(*node)
            }
            _ => {
                // Fallback to standard field access
                node.child_by_field_name("value")
            }
        }
    }
} 