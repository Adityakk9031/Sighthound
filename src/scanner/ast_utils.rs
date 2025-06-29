use tree_sitter::{Node, Tree};
use std::collections::HashMap;

/// Unified AST utilities to eliminate code duplication
pub struct AstUtils;

impl AstUtils {
    /// Extract variable name from assignment target with semantic understanding
    pub fn extract_assignment_target(code: &str) -> Option<String> {
        if let Some(eq_pos) = code.find('=') {
            let left_side = code[..eq_pos].trim();
            // Handle multiple assignments: a = b = c (take first)
            let target = left_side.split('=').next()?.trim();
            // Extract final variable name from complex expressions
            Self::extract_final_variable(target)
        } else {
            None
        }
    }
    
    /// Extract the actual variable being assigned to (not module names)
    fn extract_final_variable(expr: &str) -> Option<String> {
        // Handle patterns like: obj.attr, arr[index], simple_var
        if expr.contains('.') {
            // For obj.attr assignments, the object is modified, not a new variable
            return None;
        }
        if expr.contains('[') {
            // For arr[index], extract arr
            return expr.split('[').next().map(|s| s.trim().to_string());
        }
        // Simple variable assignment
        expr.split_whitespace().last().map(|s| s.to_string())
    }
    
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
    
    /// Check if code represents configuration (safe)
    fn is_configuration_pattern(code: &str) -> bool {
        let config_indicators = [
            "setdefault",
            "configure",
            "settings",
            "config",
            "default",
        ];
        
        config_indicators.iter().any(|&indicator| code.contains(indicator))
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
    fn is_dangerous_sink_pattern(code: &str, pattern: &str) -> bool {
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
    
    /// Extract variables from expression with semantic understanding
    pub fn extract_semantic_variables(node: &Node, source: &[u8]) -> Vec<SemanticVariable> {
        let node_text = Self::get_node_text(node, source);
        let mut variables = Vec::new();
        
        match node.kind() {
            "assignment" | "assignment_expression" => {
                if let Some(target) = Self::extract_assignment_target(&node_text) {
                    variables.push(SemanticVariable {
                        name: target,
                        var_type: VariableType::AssignmentTarget,
                        context: node_text.clone(),
                    });
                }
                
                // Extract source variables from right side
                if let Some(eq_pos) = node_text.find('=') {
                    let right_side = node_text[eq_pos + 1..].trim();
                    let source_vars = Self::extract_identifiers_from_expression(right_side);
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
                if let Some(args) = Self::extract_function_arguments(&node_text) {
                    for arg in args {
                        if Self::is_variable_name(&arg) {
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
    
    /// Extract function arguments from call expression
    fn extract_function_arguments(call_expr: &str) -> Option<Vec<String>> {
        let start = call_expr.find('(')?;
        let end = call_expr.rfind(')')?;
        let args_str = &call_expr[start + 1..end];
        
        Some(args_str.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('"') && !s.starts_with('\''))
            .collect())
    }
    
    /// Check if string is a valid variable name
    pub fn is_variable_name(s: &str) -> bool {
        !s.is_empty() && 
        s.chars().all(|c| c.is_alphanumeric() || c == '_') &&
        !s.chars().next().unwrap().is_ascii_digit()
    }
    
    /// Extract identifiers from expression (improved)
    fn extract_identifiers_from_expression(expr: &str) -> Vec<String> {
        expr.split(&[' ', '+', '-', '*', '/', '(', ')', '[', ']', '{', '}', ',', '.', '='])
            .map(|s| s.trim())
            .filter(|s| Self::is_variable_name(s))
            .map(|s| s.to_string())
            .collect()
    }
    
    /// Get node text (DRY helper)
    pub fn get_node_text(node: &Node, source: &[u8]) -> String {
        String::from_utf8_lossy(&source[node.byte_range()]).to_string()
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