use anyhow::{Context, Result};
use tree_sitter::Node;
use serde::{Deserialize, Deserializer};

// Re-export LanguageInfo from models for backward compatibility
pub use crate::models::LanguageInfo;

/// Consolidated common utilities used across the entire codebase
/// This module eliminates DRY violations by providing unified implementations
pub struct CommonUtils;

impl CommonUtils {
    // =========================================================================
    // UNIFIED TEXT EXTRACTION (consolidates 6 duplicate implementations)
    // =========================================================================

    /// Extract text from AST node using byte positions
    /// Consolidates identical logic from all language implementations
    pub fn extract_node_text(node: &Node, source: &[u8]) -> Option<String> {
        let start = node.start_byte();
        let end = node.end_byte();
        std::str::from_utf8(&source[start..end])
            .ok()
            .map(|s| s.to_string())
    }

    /// Extract text slice from AST node (zero-copy version)
    pub fn extract_node_text_slice<'a>(node: &Node, source: &'a [u8]) -> Option<&'a str> {
        let start = node.start_byte();
        let end = node.end_byte();
        std::str::from_utf8(&source[start..end]).ok()
    }

    /// Extract text from node by field name (common pattern)
    pub fn extract_field_text(node: &Node, field: &str, source: &[u8]) -> Option<String> {
        node.child_by_field_name(field)
            .and_then(|child| Self::extract_node_text(&child, source))
    }

    // =========================================================================
    // UNIFIED PATTERN MATCHING (consolidates all pattern matching implementations)
    // =========================================================================

    /// Unified pattern matching supporting exact, wildcard, glob, and regex
    pub fn matches_unified_pattern(pattern: &str, text: &str) -> bool {
        // Fast exact match
        if pattern == text {
            return true;
        }

        // Handle regex patterns (prefix or escaped chars)
        if pattern.starts_with("regex:") {
            return Self::matches_regex(&pattern[6..], text);
        }
        if pattern.contains("\\\\") || pattern.contains("\\.") {
            return Self::matches_regex(pattern, text);
        }

        // Handle escaped patterns (taint rules use escaped chars)
        if pattern.contains("\\") {
            return Self::matches_escaped_pattern(pattern, text);
        }

        // Handle glob/wildcard patterns
        if pattern.contains('*') {
            return Self::matches_wildcard(pattern, text);
        }

        // Default: substring matching
        text.contains(pattern)
    }

    /// Enhanced pattern matching supporting exact, glob, and regex patterns
    /// (Consolidated from core_utils.rs)
    pub fn matches_pattern(pattern: &str, text: &str) -> bool {
        // Fast exact match
        if pattern == text {
            return true;
        }
        
        // Glob pattern matching
        if pattern.contains('*') {
            return Self::matches_glob_pattern(pattern, text);
        }
        
        // Regex pattern matching (if pattern looks like regex)
        if Self::is_regex_pattern(pattern) {
            return Self::matches_regex_pattern(pattern, text);
        }
        
        // Substring matching with word boundaries for short patterns
        if pattern.len() <= 3 {
            Self::matches_with_word_boundary(pattern, text)
        } else {
            text.contains(pattern)
        }
    }

    /// Enhanced glob pattern matching for file paths and function names
    /// (Consolidated from core_utils.rs)
    pub fn matches_glob_pattern(pattern: &str, text: &str) -> bool {
        if !pattern.contains('*') {
            return pattern == text;
        }

        // Use glob library for complex patterns
        if let Ok(glob_pattern) = glob::Pattern::new(pattern) {
            if glob_pattern.matches(text) {
                return true;
            }
            
            // Also try matching against just the filename
            if let Some(filename) = std::path::Path::new(text).file_name() {
                if let Some(filename_str) = filename.to_str() {
                    if glob_pattern.matches(filename_str) {
                        return true;
                    }
                }
            }
        }

        // Fallback to simple wildcard matching
        Self::simple_glob_match(pattern, text)
    }

    /// Match wildcard patterns (* and ?)
    fn matches_wildcard(pattern: &str, text: &str) -> bool {
        // Convert wildcard to regex for consistent behavior
        let regex_pattern = pattern
            .replace('*', ".*")
            .replace('?', ".");
        
        Self::matches_regex(&format!("^{}$", regex_pattern), text)
    }

    /// Simple glob matching for basic wildcard patterns
    fn simple_glob_match(pattern: &str, text: &str) -> bool {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.is_empty() {
            return true;
        }
        
        if parts.len() == 2 {
            let prefix = parts[0];
            let suffix = parts[1];
            
            if prefix.is_empty() && suffix.is_empty() {
                return true; // Pattern is just "*"
            } else if prefix.is_empty() {
                return text.ends_with(suffix);
            } else if suffix.is_empty() {
                return text.starts_with(prefix);
            } else {
                return text.starts_with(prefix) && text.ends_with(suffix) && text.len() >= prefix.len() + suffix.len();
            }
        }
        
        // For complex patterns, check that all non-empty parts exist in order
        let mut current_pos = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            
            if i == 0 {
                // First part must match at start
                if !text.starts_with(part) {
                    return false;
                }
                current_pos = part.len();
            } else if i == parts.len() - 1 {
                // Last part must match at end
                return text[current_pos..].ends_with(part);
            } else {
                // Middle parts must exist in order
                if let Some(pos) = text[current_pos..].find(part) {
                    current_pos += pos + part.len();
                } else {
                    return false;
                }
            }
        }
        
        true
    }

    /// Check if pattern is a regex pattern
    fn is_regex_pattern(pattern: &str) -> bool {
        pattern.starts_with("regex:") || 
        pattern.contains("\\\\") || 
        pattern.contains("\\.")
    }

    /// Match regex patterns with error handling
    fn matches_regex(pattern: &str, text: &str) -> bool {
        regex::Regex::new(pattern)
            .map(|re| re.is_match(text))
            .unwrap_or(false)
    }

    /// Handle escaped patterns from taint rules (eval\(, os\.system, etc.)
    fn matches_escaped_pattern(pattern: &str, text: &str) -> bool {
        // Clean escaped characters for taint patterns
        let cleaned_pattern = pattern
            .replace("\\(", "(")
            .replace("\\)", ")")
            .replace("\\.", ".")
            .replace("\\\\", "\\");
        
        text.contains(&cleaned_pattern)
    }

    /// Match regex patterns (consolidated from core_utils.rs)
    fn matches_regex_pattern(pattern: &str, text: &str) -> bool {
        let regex_pattern = if pattern.starts_with("regex:") {
            &pattern[6..]
        } else {
            pattern
        };
        
        if let Ok(regex) = regex::Regex::new(regex_pattern) {
            regex.is_match(text)
        } else {
            false
        }
    }

    /// Match with word boundaries for short patterns
    fn matches_with_word_boundary(pattern: &str, text: &str) -> bool {
        if let Ok(regex) = regex::Regex::new(&format!(r"\b{}\b", regex::escape(pattern))) {
            regex.is_match(text)
        } else {
            text.contains(pattern)
        }
    }

    /// Match any pattern from a list (common use case)
    pub fn matches_any_pattern(patterns: &[String], text: &str) -> bool {
        patterns.iter().any(|pattern| Self::matches_unified_pattern(pattern, text))
    }

    // =========================================================================
    // UNIFIED VARIABLE EXTRACTION (consolidated from core_utils.rs)
    // =========================================================================

    /// Extract variable name from assignment expression with configurable behavior
    pub fn extract_variable_from_assignment(assignment_text: &str, return_empty_on_none: bool) -> Option<String> {
        let eq_pos = assignment_text.find('=')?;
        let left_side = assignment_text[..eq_pos].trim();
        
        // Handle multiple assignments: a = b = c (take first)
        let target = left_side.split('=').next()?.trim();
        
        let result = Self::extract_clean_variable_name(target);
        
        if return_empty_on_none && result.is_none() {
            Some(String::new())
        } else {
            result
        }
    }

    /// Extract clean variable name from complex expressions
    fn extract_clean_variable_name(expr: &str) -> Option<String> {
        // Handle patterns like: obj.attr, arr[index], simple_var
        if expr.contains('.') {
            // For obj.attr assignments, the object is modified, not a new variable
            return None;
        }
        if expr.contains('[') {
            // For arr[index], extract arr
            return expr.split('[').next().map(|s| s.trim().to_string());
        }
        
        // Extract final identifier from whitespace-separated expression
        expr.split_whitespace()
            .last()
            .filter(|s| Self::is_valid_variable_name(s))
            .map(|s| s.to_string())
    }

    /// Extract all variable identifiers from code expression
    pub fn extract_variables_from_expression(expr: &str) -> Vec<String> {
        let separators = [' ', '+', '-', '*', '/', '(', ')', '[', ']', '{', '}', ',', '.', '='];
        
        expr.split(&separators)
            .map(|s| s.trim())
            .filter(|s| Self::is_valid_variable_name(s))
            .filter(|s| !Self::is_keyword_or_builtin(s))
            .map(|s| s.to_string())
            .collect()
    }

    /// Extract all variables from an expression, including complex cases
    pub fn extract_all_variables_from_expression(expr: &str) -> Vec<String> {
        let mut variables = Vec::new();
        
        // Direct variable usage
        if let Some(var) = Self::extract_direct_variable(expr) {
            variables.push(var);
        }
        
        // F-string variables: f"echo {user_input}"
        variables.extend(Self::extract_f_string_variables(expr));
        
        // Format string variables: "echo {}".format(user_input)
        variables.extend(Self::extract_format_variables(expr));
        
        // String concatenation: "echo " + user_input
        variables.extend(Self::extract_concatenation_variables(expr));
        
        // Function call arguments: eval(user_input)
        variables.extend(Self::extract_function_arguments(expr).unwrap_or_default());
        
        variables
    }

    /// Extract direct variable from simple expressions
    fn extract_direct_variable(expr: &str) -> Option<String> {
        let trimmed = expr.trim();
        if Self::is_valid_variable_name(trimmed) {
            return Some(trimmed.to_string());
        }
        None
    }

    /// Extract variables from F-strings
    pub fn extract_f_string_variables(expr: &str) -> Vec<String> {
        let mut variables = Vec::new();
        let mut in_brace = false;
        let mut var_start = 0;
        
        for (i, ch) in expr.chars().enumerate() {
            match ch {
                '{' if !in_brace => {
                    in_brace = true;
                    var_start = i + 1;
                }
                '}' if in_brace => {
                    in_brace = false;
                    let var = &expr[var_start..i].trim();
                    if Self::is_valid_variable_name(var) {
                        variables.push(var.to_string());
                    }
                }
                _ => {}
            }
        }
        
        variables
    }

    /// Extract variables from format strings
    pub fn extract_format_variables(expr: &str) -> Vec<String> {
        // Handle .format() calls
        if let Some(format_start) = expr.find(".format(") {
            let args_part = &expr[format_start + 8..];
            if let Some(args_end) = args_part.rfind(')') {
                let args = &args_part[..args_end];
                return Self::extract_function_arguments(args).unwrap_or_default();
            }
        }
        
        Vec::new()
    }

    /// Extract variables from string concatenation
    fn extract_concatenation_variables(expr: &str) -> Vec<String> {
        let mut variables = Vec::new();
        
        // Handle + concatenation: "echo " + user_input
        let parts: Vec<&str> = expr.split('+').collect();
        for part in parts {
            let trimmed = part.trim();
            if Self::is_valid_variable_name(trimmed) {
                variables.push(trimmed.to_string());
            }
        }
        
        variables
    }

    /// Extract variable from various code patterns (function calls, assignments, etc.)
    pub fn extract_variable_from_code_pattern(code: &str) -> Option<String> {
        // Try assignment pattern first
        if let Some(var) = Self::extract_variable_from_assignment(code, false) {
            return Some(var);
        }
        
        // Try function call pattern
        if let Some(paren_pos) = code.find('(') {
            let before_paren = &code[..paren_pos];
            if let Some(func_name) = before_paren.split_whitespace().last() {
                if let Some(dot_pos) = func_name.rfind('.') {
                    return Some(func_name[..dot_pos].to_string());
                } else if Self::is_valid_variable_name(func_name) {
                    return Some(func_name.to_string());
                }
            }
        }
        
        None
    }

    /// Extract function arguments from call expression
    pub fn extract_function_arguments(call_expr: &str) -> Option<Vec<String>> {
        let start = call_expr.find('(')?;
        let end = call_expr.rfind(')')?;
        let args_str = &call_expr[start + 1..end];
        
        Some(args_str.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('"') && !s.starts_with('\''))
            .collect())
    }

    /// Check if assignment text is valid (not comparison)
    pub fn is_valid_assignment_text(text: &str) -> bool {
        text.contains('=') && 
        !text.contains("==") && 
        !text.contains("!=") &&
        !text.contains("<=") &&
        !text.contains(">=")
    }

    // =========================================================================
    // UNIFIED VALIDATION FUNCTIONS (consolidated from core_utils.rs)
    // =========================================================================

    /// Check if string is a valid variable name
    pub fn is_valid_variable_name(s: &str) -> bool {
        !s.is_empty() && 
        s.chars().all(|c| c.is_alphanumeric() || c == '_') &&
        !s.chars().next().unwrap().is_ascii_digit()
    }

    /// Check if string is a keyword or builtin (consolidated from multiple implementations)
    pub fn is_keyword_or_builtin(s: &str) -> bool {
        matches!(s, 
            // Python keywords
            "and" | "as" | "assert" | "break" | "class" | "continue" | "def" | "del" | "elif" | 
            "else" | "except" | "exec" | "finally" | "for" | "from" | "global" | "if" | "import" | 
            "in" | "is" | "lambda" | "not" | "or" | "pass" | "print" | "raise" | "return" | 
            "try" | "while" | "with" | "yield" |
            
            // Python builtins
            "True" | "False" | "None" | "str" | "int" | "float" | "list" | "dict" | "set" | 
            "tuple" | "bool" | "len" | "range" | "enumerate" | "zip" | "map" | "filter" |
            
            // SQL keywords
            "SELECT" | "FROM" | "WHERE" | "INSERT" | "UPDATE" | "DELETE" | "CREATE" | "DROP" |
            "ALTER" | "INDEX" | "TABLE" | "DATABASE" | "UNION" | "JOIN" | "AND" | "OR" |
            
            // JavaScript keywords (unique only)
            "var" | "let" | "const" | "function" | "do" |
            "switch" | "case" | "default" | "typeof" |
            "instanceof" | "new" | "this" | "super" | "extends" | "implements" |
            
            // Common database/web terms
            "cursor" | "execute" | "query" | "request" | "response" | "session" | "document" |
            "window" | "console" | "undefined" | "null"
        )
    }

    // =========================================================================
    // UNIFIED FILE OPERATIONS (consolidated from core_utils.rs)
    // =========================================================================

    /// Check if file path matches pattern (consolidates file type checking)
    pub fn file_matches_pattern(pattern: &str, file_path: &str) -> bool {
        // Try full path match first
        if Self::matches_pattern(pattern, file_path) {
            return true;
        }
        
        // Try filename only
        if let Some(filename) = std::path::Path::new(file_path).file_name() {
            if let Some(filename_str) = filename.to_str() {
                return Self::matches_pattern(pattern, filename_str);
            }
        }
        
        false
    }

    /// Detect syntax for syntax highlighting (moved from core.rs)
    pub fn detect_syntax(file_path: &str) -> &'static str {
        match std::path::Path::new(file_path).extension().and_then(|e| e.to_str()) {
            Some("py") => "Python",
            Some("js") | Some("mjs") => "JavaScript",
            Some("ts") | Some("tsx") => "TypeScript",
            Some("rs") => "Rust",
            Some("java") => "Java",
            Some("html") => "HTML",
            Some("css") => "CSS",
            Some("json") => "JSON",
            Some("md") => "Markdown",
            Some("sh") => "Shell",
            Some("go") => "Go",
            Some("php") => "PHP",
            Some("rb") => "Ruby",
            Some("swift") => "Swift",
            Some("kt") => "Kotlin",
            Some("scala") => "Scala",
            Some("c") => "C",
            Some("cpp") | Some("cc") | Some("cxx") | Some("hpp") => "C++",
            Some("cs") => "C#",
            Some("sql") => "SQL",
            _ => "Plain Text",
        }
    }

    // =========================================================================
    // UNIFIED AST TRAVERSAL (consolidates cursor loop patterns)
    // =========================================================================

    /// Apply function to all children and collect results
    pub fn map_children<F, T>(node: &Node, mut mapper: F) -> Vec<T>
    where
        F: FnMut(&Node) -> Option<T>,
    {
        let mut results = Vec::new();
        let mut cursor = node.walk();
        
        if cursor.goto_first_child() {
            loop {
                if let Some(result) = mapper(&cursor.node()) {
                    results.push(result);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        results
    }

    /// Apply function to all children (no return value)
    pub fn for_each_child<F>(node: &Node, mut visitor: F)
    where
        F: FnMut(&Node),
    {
        let mut cursor = node.walk();
        
        if cursor.goto_first_child() {
            loop {
                visitor(&cursor.node());
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Find first child matching predicate
    pub fn find_child<'a, F>(node: &'a Node<'a>, mut predicate: F) -> Option<Node<'a>>
    where
        F: FnMut(&Node) -> bool,
    {
        let mut cursor = node.walk();
        
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if predicate(&child) {
                    return Some(child);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        None
    }

    /// Recursive tree traversal with depth limit
    pub fn traverse_recursive<F>(node: &Node, visitor: &mut F, max_depth: usize)
    where
        F: FnMut(&Node),
    {
        if max_depth == 0 {
            return;
        }

        visitor(node);
        
        Self::for_each_child(node, |child| {
            Self::traverse_recursive(&child, visitor, max_depth - 1);
        });
    }

    // =========================================================================
    // UNIFIED ERROR HANDLING (consolidates anyhow patterns)
    // =========================================================================

    /// Standard context wrapper for file operations
    pub fn file_context(operation: String, path: String) -> impl Fn(std::io::Error) -> anyhow::Error {
        move |e| anyhow::anyhow!("Failed to {} file '{}': {}", operation, path, e)
    }

    /// Standard context wrapper for parsing operations
    pub fn parse_context(file_type: String, path: String) -> impl Fn(Box<dyn std::error::Error>) -> anyhow::Error {
        move |e| anyhow::anyhow!("Failed to parse {} file '{}': {}", file_type, path, e)
    }

    /// Load and parse file with unified error handling
    pub fn load_and_parse<T>(path: &str, parser: impl FnOnce(&str) -> Result<T>) -> Result<T> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read file: {}", path))?;
        
        parser(&content)
            .with_context(|| format!("Failed to parse file: {}", path))
    }

    // =========================================================================
    // UNIFIED SERDE UTILITIES (consolidates custom deserializers)
    // =========================================================================

    /// Generic optional string deserializer (handles both "value" and Some("value"))
    pub fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, Visitor};
        use std::fmt;

        struct OptionalStringVisitor;

        impl<'de> Visitor<'de> for OptionalStringVisitor {
            type Value = Option<String>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or Option<String>")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Some(value.to_string()))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                Ok(Some(String::deserialize(deserializer)?))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }
        }

        deserializer.deserialize_any(OptionalStringVisitor)
    }

    /// Generic optional vector deserializer (handles both ["val1", "val2"] and Some(["val1", "val2"]))
    pub fn deserialize_optional_vector<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, Visitor};
        use std::fmt;

        struct OptionalVectorVisitor;

        impl<'de> Visitor<'de> for OptionalVectorVisitor {
            type Value = Option<Vec<String>>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of strings or Option<Vec<String>>")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(elem) = seq.next_element()? {
                    vec.push(elem);
                }
                Ok(Some(vec))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                Ok(Some(Vec::<String>::deserialize(deserializer)?))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }
        }

        deserializer.deserialize_any(OptionalVectorVisitor)
    }

    // =========================================================================
    // UNIFIED LANGUAGE SUPPORT UTILITIES
    // =========================================================================

    /// Get standard field-based function name (common pattern)
    pub fn get_standard_function_name<'a>(node: &'a Node<'a>, source: &[u8], field: &str) -> Option<String> {
        node.child_by_field_name(field)
            .and_then(|child| Self::extract_node_text(&child, source))
    }

    /// Get standard arguments node (common pattern)
    pub fn get_standard_arguments_node<'a>(node: &'a Node<'a>) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }

    // =========================================================================
    // UNIFIED VALIDATION & DEFAULTS
    // =========================================================================

    /// Validate required CLI parameter combination
    pub fn validate_cli_params(language: &Option<String>, rules_path: &Option<String>) -> Result<()> {
        match (language, rules_path) {
            (Some(_), Some(_)) | (None, None) => Ok(()),
            _ => Err(anyhow::anyhow!(
                "Invalid combination. Provide both language and rules path, or use auto-detection"
            )),
        }
    }

    /// Get default severity with fallback
    pub fn get_default_severity(severity: &Option<String>) -> String {
        severity.clone().unwrap_or_else(|| "Medium".to_string())
    }

    /// Get default confidence with fallback
    pub fn get_default_confidence(confidence: &Option<String>) -> String {
        confidence.clone().unwrap_or_else(|| "Medium".to_string())
    }
} 