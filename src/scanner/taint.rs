use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use crate::rules::Rules;
use crate::language::LanguageSupport;
use crate::parser::get_node_text;
use tree_sitter::{Node, Tree};

// Constants for taint analysis
const DEFAULT_SEVERITY: &str = "High";
const DEFAULT_CONFIDENCE: &str = "Medium";
const DEFAULT_FUNCTION: &str = "global";
const ASSIGNMENT_NODES: &[&str] = &["assignment", "assignment_expression", "expression_statement"];
const FUNCTION_NODES: &[&str] = &["function_definition", "method_definition"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisResult {
    pub flows: Vec<TaintFlow>,
    pub summary: TaintSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    pub flow_id: String,
    pub flow_name: Option<String>,
    pub severity: String,
    pub confidence: String,
    pub source: TaintSource,
    pub sink: TaintSink,
    pub traces: Vec<TaintTrace>,
    pub is_sanitized: bool,
    pub sanitization_points: Vec<TaintTrace>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    pub file: String,
    pub line: usize,
    pub function: String,
    pub variable: String,
    pub operation: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    pub file: String,
    pub line: usize,
    pub function: String,
    pub variable: String,
    pub operation: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintTrace {
    pub file: String,
    pub line: usize,
    pub function: String,
    pub variable: String,
    pub operation: String,
    pub code: String,
    pub trace_type: TraceType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TraceType {
    Propagation,
    Assignment,
    Sanitization,
    FunctionCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSummary {
    pub total_flows: usize,
    pub unsanitized_flows: usize,
    pub sanitized_flows: usize,
    pub files_analyzed: usize,
    pub functions_analyzed: usize,
}

pub struct TaintAnalyzer {
    rules: Rules,
    variable_tracker: VariableTracker,
}

struct VariableTracker {
    // Maps variable names to their taint status and flow IDs
    tainted_vars: HashMap<String, TaintInfo>,
}

#[derive(Debug, Clone)]
struct TaintInfo {
    // Simplified - removed unused fields that were never read
}

impl TaintAnalyzer {
    pub fn new(rules: Rules) -> Self {
        Self {
            rules,
            variable_tracker: VariableTracker::new(),
        }
    }

    pub fn analyze_file(
        &mut self,
        filepath: &str,
        source: &[u8],
        tree: &Tree,
        language_support: &dyn LanguageSupport,
    ) -> TaintAnalysisResult {
        let mut flows = Vec::new();
        let mut sources = Vec::with_capacity(32); // Pre-allocate with reasonable capacity
        let mut sinks = Vec::with_capacity(32);
        
        // Reset variable tracker for each file
        self.variable_tracker.reset();
        
        // First pass: find all sources and sinks
        self.find_sources_and_sinks(tree.root_node(), source, filepath, language_support, &mut sources, &mut sinks);
        
        // Deduplicate sources and sinks more efficiently
        self.deduplicate_sources(&mut sources);
        self.deduplicate_sinks(&mut sinks);
        
        // Second pass: track data flows between sources and sinks
        let mut seen_flows = HashSet::with_capacity(sources.len() * sinks.len());
        
        for source_item in &sources {
            if let Some(flow) = self.trace_flow_from_source(source_item, &sinks, tree, source, language_support) {
                // Extract values for the key before moving flow
                let sink_line = flow.sink.line;
                let sink_operation = flow.sink.operation.clone();
                
                // Create a unique key for deduplication using owned strings
                let flow_key = (source_item.line, source_item.operation.clone(), sink_line, sink_operation);
                
                if seen_flows.insert(flow_key) {
                    flows.push(flow);
                }
            }
        }
        
        let summary = TaintSummary {
            total_flows: flows.len(),
            unsanitized_flows: flows.iter().filter(|f| !f.is_sanitized).count(),
            sanitized_flows: flows.iter().filter(|f| f.is_sanitized).count(),
            files_analyzed: 1,
            functions_analyzed: self.count_functions(tree.root_node()),
        };
        
        TaintAnalysisResult { flows, summary }
    }

    fn find_sources_and_sinks(
        &mut self,
        node: Node,
        source: &[u8],
        filepath: &str,
        language_support: &dyn LanguageSupport,
        sources: &mut Vec<TaintSource>,
        sinks: &mut Vec<TaintSink>,
    ) {
        // Only check specific node types that could be sources/sinks
        // Be more selective to reduce duplicates
        let should_check = match node.kind() {
            "assignment" | "assignment_expression" | "expression_statement" => true,
            _ => false,
        };
        
        if should_check {
            let node_text = get_node_text(&node, source);
            let function_name = self.get_containing_function(&node, source);
            
            // Debug: print node info for troubleshooting
            // println!("DEBUG: Checking node type '{}' with text: '{}'", node.kind(), node_text.trim());
            
            // Check for taint sources and sinks in unified rules with taint mode
            for unified_rule in &self.rules.rules {
                if unified_rule.is_taint_rule() {
                    // Check sources
                    if let Some(source_patterns) = &unified_rule.sources {
                        for pattern in source_patterns {
                            if self.matches_taint_pattern(pattern, &node_text) {
                                let variable = self.extract_variable_from_node(&node, source, None);
                                let taint_source = TaintSource {
                                    file: filepath.to_string(),
                                    line: node.start_position().row + 1,
                                    function: function_name.clone(),
                                    variable: variable.clone(),
                                    operation: pattern.to_string(),
                                    code: self.get_line_text(&node, source),
                                };
                                sources.push(taint_source);
                                
                                // Track this variable as tainted
                                let flow_id = format!("flow_{}", sources.len());
                                self.variable_tracker.mark_tainted(variable, flow_id, filepath.to_string(), node.start_position().row + 1, pattern.to_string());
                            }
                        }
                    }
                    
                    // Check sinks
                    if let Some(sink_patterns) = &unified_rule.sinks {
                        for pattern in sink_patterns {
                            if self.matches_taint_pattern(pattern, &node_text) {
                                let variable = self.extract_variable_from_node(&node, source, Some(pattern));
                                let taint_sink = TaintSink {
                                    file: filepath.to_string(),
                                    line: node.start_position().row + 1,
                                    function: function_name.clone(),
                                    variable: variable.clone(),
                                    operation: pattern.to_string(),
                                    code: self.get_line_text(&node, source),
                                };
                                sinks.push(taint_sink);
                            }
                        }
                    }
                }
            }
        }
        
        // Recursively check child nodes
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.find_sources_and_sinks(cursor.node(), source, filepath, language_support, sources, sinks);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn trace_flow_from_source(
        &self,
        source: &TaintSource,
        sinks: &[TaintSink],
        tree: &Tree,
        source_bytes: &[u8],
        language_support: &dyn LanguageSupport,
    ) -> Option<TaintFlow> {
        // Find sinks that use the same variable or are reachable from the source
        for sink in sinks {
            if self.is_flow_reachable(source, sink, tree, source_bytes, language_support) {
                let flow_id = format!("flow_{}_{}", source.line, sink.line);
                let traces = self.find_traces_between(source, sink, tree, source_bytes, language_support);
                let (is_sanitized, sanitization_points) = self.check_sanitization(&traces);
                
                return Some(TaintFlow {
                    flow_id,
                    flow_name: Some(format!("{} -> {}", source.operation, sink.operation)),
                    severity: DEFAULT_SEVERITY.to_string(),
                    confidence: DEFAULT_CONFIDENCE.to_string(),
                    source: source.clone(),
                    sink: sink.clone(),
                    traces,
                    is_sanitized,
                    sanitization_points,
                });
            }
        }
        None
    }

    fn is_flow_reachable(
        &self,
        source: &TaintSource,
        sink: &TaintSink,
        tree: &Tree,
        source_bytes: &[u8],
        _language_support: &dyn LanguageSupport,
    ) -> bool {
        // Flows must be in the same file and same function
        if source.file != sink.file || source.function != sink.function {
            return false;
        }
        
        // Source must come before sink
        if source.line >= sink.line {
            return false;
        }
        
        // Check for direct variable match or variable connection chain
        source.variable == sink.variable ||
        self.has_variable_connection(&source.variable, &sink.variable, tree, source_bytes) ||
        self.check_transitive_connection(&source.variable, &sink.variable, tree, source_bytes)
    }

    fn has_variable_connection(&self, source_var: &str, sink_var: &str, tree: &Tree, source: &[u8]) -> bool {
        // Look for assignment chains like: a = source; b = a; sink(b)
        // This is a simplified implementation
        let root = tree.root_node();
        self.find_assignment_chain(root, source_var, sink_var, source, &mut HashSet::new())
    }

    fn check_transitive_connection(&self, source_var: &str, sink_var: &str, tree: &Tree, source: &[u8]) -> bool {
        // Check for transitive connections through intermediate variables
        // Example: user_id -> query -> cursor.execute(query)
        let mut intermediate_vars = Vec::new();
        
        // Find all variables that are assigned from source_var
        self.find_variables_assigned_from(tree.root_node(), source_var, source, &mut intermediate_vars);
        
        // Check if any intermediate variable connects to the sink
        for intermediate in &intermediate_vars {
            if intermediate == sink_var || 
               self.variable_used_in_expression(tree.root_node(), intermediate, sink_var, source) {
                return true;
            }
        }
        
        false
    }

    fn find_variables_assigned_from(&self, node: Node, source_var: &str, source: &[u8], results: &mut Vec<String>) {
        let node_text = get_node_text(&node, source);
        
        // Look for assignments like "new_var = source_var" or "new_var = f'...{source_var}...'"
        if (node.kind() == "assignment" || node.kind() == "expression_statement") && node_text.contains('=') {
            if node_text.contains(source_var) {
                if let Some(equals_pos) = node_text.find('=') {
                    let left_side = node_text[..equals_pos].trim();
                    if let Some(var_name) = left_side.split_whitespace().last() {
                        if var_name != source_var && !results.contains(&var_name.to_string()) {
                            results.push(var_name.to_string());
                        }
                    }
                }
            }
        }
        
        // Recursively check children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.find_variables_assigned_from(cursor.node(), source_var, source, results);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn variable_used_in_expression(&self, node: Node, var_name: &str, sink_var: &str, source: &[u8]) -> bool {
        let node_text = get_node_text(&node, source);
        
        // Check if var_name is used in an expression that assigns to or uses sink_var
        if node_text.contains(var_name) && node_text.contains(sink_var) {
            return true;
        }
        
        // Recursively check children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if self.variable_used_in_expression(cursor.node(), var_name, sink_var, source) {
                    return true;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        false
    }

    fn find_assignment_chain(&self, node: Node, source_var: &str, target_var: &str, source: &[u8], visited: &mut HashSet<String>) -> bool {
        let node_text = get_node_text(&node, source);
        
        // Check for assignment patterns like "target = source"
        if node.kind() == "assignment" || node.kind() == "expression_statement" {
            if node_text.contains(&format!("{} =", target_var)) && node_text.contains(source_var) {
                return true;
            }
        }
        
        // Recursively check children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if self.find_assignment_chain(cursor.node(), source_var, target_var, source, visited) {
                    return true;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        false
    }

    fn find_traces_between(
        &self,
        source: &TaintSource,
        sink: &TaintSink,
        tree: &Tree,
        source_bytes: &[u8],
        _language_support: &dyn LanguageSupport,
    ) -> Vec<TaintTrace> {
        let mut traces = Vec::new();
        
        // Find meaningful intermediate steps between source and sink
        let root = tree.root_node();
        self.collect_meaningful_traces(
            root,
            source,
            sink,
            source_bytes,
            &mut traces,
        );
        
        // Deduplicate and sort traces
        traces.sort_by(|a, b| a.line.cmp(&b.line));
        traces.dedup_by(|a, b| a.line == b.line && a.operation == b.operation);
        
        traces
    }

    fn collect_meaningful_traces(
        &self,
        node: Node,
        source: &TaintSource,
        sink: &TaintSink,
        source_bytes: &[u8],
        traces: &mut Vec<TaintTrace>,
    ) {
        let node_line = node.start_position().row + 1;
        
        // Only collect traces between source and sink lines
        if node_line > source.line && node_line < sink.line {
            let node_text = get_node_text(&node, source_bytes);
            
            // Only collect meaningful assignments and propagations
            let is_meaningful = match node.kind() {
                "assignment" | "assignment_expression" => {
                    // Check if this assignment involves our tracked variable
                    node_text.contains(&source.variable) && node_text.contains('=')
                },
                "expression_statement" => {
                    // Check if this is an assignment statement involving our variable
                    node_text.contains(&source.variable) && node_text.contains('=')
                },
                _ => false,
            };
            
            if is_meaningful {
                let function_name = self.get_containing_function(&node, source_bytes);
                
                // Extract the variable being assigned to
                let assigned_var = if let Some(equals_pos) = node_text.find('=') {
                    let left_side = node_text[..equals_pos].trim();
                    left_side.split_whitespace().last().unwrap_or("unknown_var").to_string()
                } else {
                    source.variable.clone()
                };
                
                let trace = TaintTrace {
                    file: source.file.clone(),
                    line: node_line,
                    function: function_name,
                    variable: assigned_var,
                    operation: "assignment".to_string(),
                    code: self.get_line_text(&node, source_bytes),
                    trace_type: TraceType::Assignment,
                };
                
                traces.push(trace);
            }
        }
        
        // Recursively check children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.collect_meaningful_traces(cursor.node(), source, sink, source_bytes, traces);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn check_sanitization(&self, traces: &[TaintTrace]) -> (bool, Vec<TaintTrace>) {
        let mut sanitization_points = Vec::new();
        let mut is_sanitized = false;
        
        for trace in traces {
            if trace.trace_type == TraceType::Sanitization {
                sanitization_points.push(trace.clone());
                is_sanitized = true;
            }
        }
        
        (is_sanitized, sanitization_points)
    }

    fn get_line_text(&self, node: &Node, source: &[u8]) -> String {
        // Get the line number of the node
        let line_num = node.start_position().row;
        
        // Convert source to string safely
        let source_str = match std::str::from_utf8(source) {
            Ok(s) => s,
            Err(_) => return "Unable to decode text".to_string(),
        };
        
        // Split into lines and get the specific line
        let lines: Vec<&str> = source_str.lines().collect();
        
        if line_num < lines.len() {
            lines[line_num].trim().to_string()
        } else {
            // Fallback to node text if line number is out of bounds
            get_node_text(node, source).trim().to_string()
        }
    }

    fn matches_taint_pattern(&self, pattern: &str, text: &str) -> bool {
        // More robust pattern matching with error handling
        if pattern.is_empty() || text.is_empty() {
            return false;
        }
        
        // Handle different pattern types safely
        if pattern.contains('*') {
            // Simple wildcard matching
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                text.starts_with(parts[0]) && text.ends_with(parts[1])
            } else {
                text.contains(&pattern.replace('*', ""))
            }
        } else {
            text.contains(pattern)
        }
    }

    fn extract_variable_from_node(&self, node: &Node, source: &[u8], pattern: Option<&str>) -> String {
        let node_text = get_node_text(node, source);
        
        // Try different extraction strategies based on context
        if let Some(pattern) = pattern {
            // For sink patterns, look for the variable being passed to the dangerous function
            if let Some(paren_pos) = pattern.find('(') {
                let func_name = &pattern[..paren_pos];
                if node_text.contains(func_name) {
                    if let Some(start) = node_text.find('(') {
                        if let Some(end) = node_text.find(')') {
                            if start < end {
                                let args = &node_text[start + 1..end];
                                return args.split(',').next()
                                    .unwrap_or("unknown_var")
                                    .trim()
                                    .to_string();
                            }
                        }
                    }
                }
            }
        }
        
        // For assignments, extract the left-hand side variable
        if ASSIGNMENT_NODES.contains(&node.kind()) && node_text.contains('=') {
            if let Some(equals_pos) = node_text.find('=') {
                let left_side = node_text[..equals_pos].trim();
                if let Some(var_name) = left_side.split_whitespace().last() {
                    return var_name.to_string();
                }
            }
        }
        
        // Fallback: try to extract identifier from node structure
        self.extract_identifier_from_tree(node, source)
            .unwrap_or_else(|| "unknown_var".to_string())
    }
    
    fn extract_identifier_from_tree(&self, node: &Node, source: &[u8]) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source));
        }
        
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if let Some(identifier) = self.extract_identifier_from_tree(&cursor.node(), source) {
                    return Some(identifier);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        None
    }

    fn get_containing_function(&self, node: &Node, source: &[u8]) -> String {
        let mut current = *node;
        
        loop {
            if FUNCTION_NODES.contains(&current.kind()) {
                // Try to get function name from the node
                let mut cursor = current.walk();
                if cursor.goto_first_child() {
                    loop {
                        if cursor.node().kind() == "identifier" {
                            return get_node_text(&cursor.node(), source);
                        }
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
            
            if let Some(parent) = current.parent() {
                current = parent;
            } else {
                break;
            }
        }
        
        DEFAULT_FUNCTION.to_string()
    }

    fn count_functions(&self, node: Node) -> usize {
        let mut count = 0;
        
        if FUNCTION_NODES.contains(&node.kind()) {
            count += 1;
        }
        
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                count += self.count_functions(cursor.node());
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        count
    }

    fn deduplicate_sources(&self, sources: &mut Vec<TaintSource>) {
        sources.sort_by(|a, b| a.line.cmp(&b.line).then(a.operation.cmp(&b.operation)));
        sources.dedup_by(|a, b| a.line == b.line && a.operation == b.operation);
    }
    
    fn deduplicate_sinks(&self, sinks: &mut Vec<TaintSink>) {
        sinks.sort_by(|a, b| a.line.cmp(&b.line).then(a.operation.cmp(&b.operation)));
        sinks.dedup_by(|a, b| a.line == b.line && a.operation == b.operation);
    }
}

impl VariableTracker {
    fn new() -> Self {
        Self {
            tainted_vars: HashMap::new(),
        }
    }

    fn reset(&mut self) {
        self.tainted_vars.clear();
    }

    fn mark_tainted(&mut self, variable: String, _flow_id: String, _file: String, _line: usize, _taint_type: String) {
        // Simplified implementation - just track that variable exists
        self.tainted_vars.insert(variable, TaintInfo {});
    }
} 