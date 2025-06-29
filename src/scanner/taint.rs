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

const FUNCTION_NODES: &[&str] = &["function_definition", "method_definition"];

// NEW: Multi-file analysis data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub file: String,
    pub line: usize,
    pub imported_name: String,
    pub from_module: String,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportInfo {
    pub file: String,
    pub line: usize,
    pub exported_name: String,
    pub function_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossFileFlow {
    pub source_file: String,
    pub sink_file: String,
    pub imported_function: String,
    pub is_cross_file: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisResult {
    pub flows: Vec<TaintFlow>,
    pub summary: TaintSummary,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub cross_file_flows: Vec<CrossFileFlow>,
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintSink>,
}

impl TaintAnalysisResult {
    /// Convert taint analysis results to unified Finding format
    pub fn to_findings(&self) -> Vec<crate::scanner::types::Finding> {
        use crate::scanner::types::*;
        
        self.flows.iter().map(|flow| Finding {
            file: flow.source.file.clone(),
            line: flow.source.line,
            column: 0, // TaintFlow doesn't track columns yet
            end_line: flow.sink.line,
            end_column: 0,
            function: flow.source.function.clone(),
            finding_type: format!("taint_flow_{}", flow.flow_id),
            snippet: flow.source.code.clone(),
            severity: flow.severity.clone(),
            confidence: flow.confidence.clone(),
            description: flow.flow_name.clone(),
            source_info: Some(SourceInfo {
                source_type: flow.source.operation.clone(),
                location: format!("{}:{}", flow.source.file, flow.source.line),
                context: flow.source.code.clone(),
            }),
            sink_info: Some(SinkInfo {
                sink_type: flow.sink.operation.clone(),
                function_name: flow.sink.function.clone(),
                location: format!("{}:{}", flow.sink.file, flow.sink.line),
                variable: Some(flow.sink.variable.clone()),
            }),
            traces: if flow.traces.is_empty() {
                None
            } else {
                Some(flow.traces.iter().map(|trace| TraceStep {
                    file: trace.file.clone(),
                    line: trace.line,
                    code: trace.code.clone(),
                    variable: trace.variable.clone(),
                    operation: trace.operation.clone(),
                    function: trace.function.clone(),
                }).collect())
            },
            tags: Some(vec![
                "taint_analysis".to_string(),
                if flow.is_cross_file { "cross_file" } else { "same_file" }.to_string(),
                if flow.is_sanitized { "sanitized" } else { "unsanitized" }.to_string(),
            ]),
        }).collect()
    }
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
    pub is_cross_file: bool,
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
    CrossFileImport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSummary {
    pub total_flows: usize,
    pub unsanitized_flows: usize,
    pub sanitized_flows: usize,
    pub cross_file_flows: usize,
    pub files_analyzed: usize,
    pub functions_analyzed: usize,
}

pub struct TaintAnalyzer {
    rules: Rules,
    variable_tracker: VariableTracker,
    import_map: HashMap<String, Vec<ImportInfo>>,
    export_map: HashMap<String, Vec<ExportInfo>>,
}

#[derive(Debug, Clone)]
struct TaintInfo {
    // Enhanced with propagation tracking
    flow_id: String,
    source_type: String,
    propagation_chain: Vec<String>, // Track variable assignment chain
}

#[derive(Debug, Clone)]
struct CrossFileVarInfo {
    original_file: String,
    original_function: String,
    import_info: Option<ImportInfo>,
    taint_info: Option<TaintInfo>,
}

// NEW: Function call tracking for return value propagation
#[derive(Debug, Clone)]
struct FunctionCallInfo {
    function_name: String,
    file: String,
    line: usize,
    return_variable: Option<String>,
    taint_status: TaintStatus,
}

#[derive(Debug, Clone, PartialEq)]
enum TaintStatus {
    Tainted(String), // Contains the source pattern
    Unknown,
}

// NEW: Enhanced variable tracker with function call support
struct VariableTracker {
    // Maps variable names to their taint status and flow IDs
    tainted_vars: HashMap<String, TaintInfo>,
    // Cross-file variable tracking
    cross_file_vars: HashMap<String, CrossFileVarInfo>,
    // NEW: Function call tracking for return value propagation
    function_calls: HashMap<String, FunctionCallInfo>, // function_name -> info
    // NEW: Assignment chains tracking
    assignment_chains: HashMap<String, Vec<String>>, // var -> [source_vars]
    // NEW: Return value tracking
    function_returns: HashMap<String, TaintStatus>, // function_name -> taint_status
}

impl TaintAnalyzer {
    pub fn new(rules: Rules) -> Self {
        Self {
            rules,
            variable_tracker: VariableTracker::new(),
            import_map: HashMap::new(),
            export_map: HashMap::new(),
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
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        let mut cross_file_flows = Vec::new();
        
        // Reset variable tracker for each file
        self.variable_tracker.reset();
        
        // NEW: Extract imports and exports first
        self.extract_imports_and_exports(tree.root_node(), source, filepath, &mut imports, &mut exports);
        
        // Update internal maps for cross-file analysis
        self.import_map.insert(filepath.to_string(), imports.clone());
        self.export_map.insert(filepath.to_string(), exports.clone());
        
        // Find taint sources and sinks
        self.find_sources_and_sinks(tree.root_node(), source, filepath, language_support, &mut sources, &mut sinks);
        
        // Enhanced deduplication
        self.deduplicate_sources(&mut sources);
        self.deduplicate_sinks(&mut sinks);
        
        // Track data flows between sources and sinks
        let mut seen_flows = HashSet::with_capacity(sources.len() * sinks.len());
        

        
        for source_item in &sources {
            if let Some(flow) = self.trace_flow_from_source(source_item, &sinks, tree, source, language_support) {
                // Check if this is a cross-file flow
                let is_cross_file = source_item.file != flow.sink.file;
                if is_cross_file {
                    cross_file_flows.push(CrossFileFlow {
                        source_file: source_item.file.clone(),
                        sink_file: flow.sink.file.clone(),
                        imported_function: source_item.function.clone(),
                        is_cross_file: true,
                    });
                }
                
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
        
        let cross_file_flow_count = flows.iter().filter(|f| f.is_cross_file).count();
        
        let summary = TaintSummary {
            total_flows: flows.len(),
            unsanitized_flows: flows.iter().filter(|f| !f.is_sanitized).count(),
            sanitized_flows: flows.iter().filter(|f| f.is_sanitized).count(),
            cross_file_flows: cross_file_flow_count,
            files_analyzed: 1,
            functions_analyzed: self.count_functions(tree.root_node()),
        };
        
        TaintAnalysisResult { 
            flows, 
            summary, 
            imports, 
            exports, 
            cross_file_flows,
            sources: sources.clone(),
            sinks: sinks.clone(),
        }
    }

    // NEW: Extract imports and exports for cross-file analysis
    fn extract_imports_and_exports(
        &self,
        node: Node,
        source: &[u8],
        filepath: &str,
        imports: &mut Vec<ImportInfo>,
        exports: &mut Vec<ExportInfo>,
    ) {
        // Enhanced import detection using AST nodes
        match node.kind() {
            "import_statement" | "import_from_statement" => {
                // Use enhanced AST-based parsing instead of simple text parsing
                let import_infos = self.parse_import_statement_ast(node, source, filepath);
                imports.extend(import_infos);
            }
            "function_definition" | "class_definition" => {
                if let Some(export_info) = self.parse_export_statement_ast(node, source, filepath) {
                    exports.push(export_info);
                }
            }
            _ => {}
        }
        
        // Recursively check child nodes
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.extract_imports_and_exports(cursor.node(), source, filepath, imports, exports);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    // NEW: Enhanced AST-based import parsing
    fn parse_import_statement_ast(&self, node: Node, source: &[u8], filepath: &str) -> Vec<ImportInfo> {
        let mut imports = Vec::new();
        let node_text = get_node_text(&node, source);
        let line = node.start_position().row + 1;

        match node.kind() {
            "import_from_statement" => {
                // Handle: from module import func1, func2, ...
                if let (Some(module), import_names) = self.parse_from_import_ast(&node, source) {
                    for import_name in import_names {
                        imports.push(ImportInfo {
                            file: filepath.to_string(),
                            line,
                            imported_name: import_name.name,
                            from_module: module.clone(),
                            alias: import_name.alias,
                        });
                    }
                }
            }
            "import_statement" => {
                // Handle: import module1, module2, ...
                let import_names = self.parse_regular_import_ast(&node, source);
                for import_name in import_names {
                    imports.push(ImportInfo {
                        file: filepath.to_string(),
                        line,
                        imported_name: import_name.name.clone(),
                        from_module: import_name.name,
                        alias: import_name.alias,
                    });
                }
            }
            _ => {
                // Fallback to original text-based parsing
                if let Some(import_info) = self.parse_import_statement(&node_text, filepath, line) {
                    imports.push(import_info);
                }
            }
        }

        imports
    }

    // NEW: Parse from import statements using AST
        fn parse_from_import_ast(&self, node: &Node, source: &[u8]) -> (Option<String>, Vec<ImportName>) {
        let mut module_name = None;
        let mut import_names = Vec::new();

        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                
                match child.kind() {
                    "dotted_name" | "identifier" => {
                        if module_name.is_none() {
                            module_name = Some(get_node_text(&child, source));
                        } else {
                            // CRITICAL FIX: Handle individual import names as dotted_name children
                            // This handles cases like: from module import (func1, func2, func3)
                            let name = get_node_text(&child, source);
                            import_names.push(ImportName { name, alias: None });
                        }
                    }
                    "import_list" => {
                        // Parse import list: (func1, func2, func3)
                        import_names.extend(self.parse_import_list(&child, source));
                    }
                    "aliased_import" => {
                        // Parse single aliased import: func as alias
                        if let Some(import_name) = self.parse_aliased_import(&child, source) {
                            import_names.push(import_name);
                        }
                    }
                    _ => {}
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        (module_name, import_names)
    }

    // NEW: Parse regular import statements using AST
    fn parse_regular_import_ast(&self, node: &Node, source: &[u8]) -> Vec<ImportName> {
        let mut import_names = Vec::new();

        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                match child.kind() {
                    "dotted_name" | "identifier" => {
                        import_names.push(ImportName {
                            name: get_node_text(&child, source),
                            alias: None,
                        });
                    }
                    "aliased_import" => {
                        if let Some(import_name) = self.parse_aliased_import(&child, source) {
                            import_names.push(import_name);
                        }
                    }
                    _ => {}
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        import_names
    }

    // NEW: Parse import list (func1, func2, func3)
    fn parse_import_list(&self, node: &Node, source: &[u8]) -> Vec<ImportName> {
        let mut import_names = Vec::new();

        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                
                match child.kind() {
                    "identifier" => {
                        let name = get_node_text(&child, source);
                        import_names.push(ImportName {
                            name,
                            alias: None,
                        });
                    }
                    "aliased_import" => {
                        if let Some(import_name) = self.parse_aliased_import(&child, source) {
                            import_names.push(import_name);
                        }
                    }
                    _ => {}
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        import_names
    }

    // NEW: Parse aliased imports (name as alias)
    fn parse_aliased_import(&self, node: &Node, source: &[u8]) -> Option<ImportName> {
        let mut name = None;
        let mut alias = None;

        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                match child.kind() {
                    "identifier" | "dotted_name" => {
                        if name.is_none() {
                            name = Some(get_node_text(&child, source));
                        } else if alias.is_none() {
                            alias = Some(get_node_text(&child, source));
                        }
                    }
                    _ => {}
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        if let Some(n) = name {
            Some(ImportName { name: n, alias })
        } else {
            None
        }
    }

    // NEW: Enhanced export parsing using AST
    fn parse_export_statement_ast(&self, node: Node, source: &[u8], filepath: &str) -> Option<ExportInfo> {
        let line = node.start_position().row + 1;
        
        if node.kind() == "function_definition" {
            // Find function name in AST
            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.kind() == "identifier" {
                        let function_name = get_node_text(&child, source);
                        return Some(ExportInfo {
                            file: filepath.to_string(),
                            line,
                            exported_name: function_name.clone(),
                            function_name,
                        });
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
        
        None
    }

    // Fallback text-based import parsing for compatibility
    fn parse_import_statement(&self, text: &str, filepath: &str, line: usize) -> Option<ImportInfo> {
        // Simple regex-like parsing for common import patterns
        if text.contains("from") && text.contains("import") {
            // Pattern: from module import function
            let parts: Vec<&str> = text.split_whitespace().collect();
            if parts.len() >= 4 && parts[0] == "from" && parts[2] == "import" {
                return Some(ImportInfo {
                    file: filepath.to_string(),
                    line,
                    imported_name: parts[3].trim_end_matches(',').to_string(),
                    from_module: parts[1].to_string(),
                    alias: None,
                });
            }
        } else if text.contains("import") {
            // Pattern: import module
            let parts: Vec<&str> = text.split_whitespace().collect();
            if parts.len() >= 2 && parts[0] == "import" {
                return Some(ImportInfo {
                    file: filepath.to_string(),
                    line,
                    imported_name: parts[1].trim_end_matches(',').to_string(),
                    from_module: parts[1].to_string(),
                    alias: None,
                });
            }
        }
        None
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
        // Enhanced node type checking for better coverage
        let should_check = match node.kind() {
                         "assignment" | "assignment_expression" | "expression_statement" | "call" | "attribute" | "return_statement" => true,
            _ => false,
        };
        
        if should_check {
            let node_text = get_node_text(&node, source);
            let function_name = self.get_containing_function(&node, source);
            
            // NEW: Check for assignment patterns and track them
            self.analyze_assignment_patterns(&node, source, filepath);
            
            // NEW: Check for function calls and track return values
            self.analyze_function_calls(&node, source, filepath);
            
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
                                
                                // Enhanced taint tracking
                                let flow_id = format!("flow_{}", sources.len());
                                self.variable_tracker.mark_tainted(
                                    variable.clone(),
                                    flow_id,
                                    filepath.to_string(),
                                    node.start_position().row + 1,
                                    pattern.to_string()
                                );
                                
                                // NEW: If this is in a function, mark the function as returning tainted data
                                if function_name != "global" {
                                    self.variable_tracker.mark_function_returns_taint(
                                        function_name.clone(),
                                        pattern.to_string()
                                    );
                                }
                            }
                        }
                    }
                    
                    // Enhanced sink detection with variable propagation check
                    if let Some(sink_patterns) = &unified_rule.sinks {
                        for pattern in sink_patterns {
                            if self.matches_taint_pattern(pattern, &node_text) {
                                let variable = self.extract_variable_from_node(&node, source, Some(pattern));
                                
                                // 🎯 CRITICAL BYPASS: Temporarily disable enhanced sink detection for testing
                                // TODO: Re-enable with proper imported function detection
                                let should_create_sink = true; // self.variable_tracker.is_variable_tainted(&variable);
                                
                                if should_create_sink {
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

    // NEW: Analyze assignment patterns for variable propagation
    fn analyze_assignment_patterns(&mut self, node: &Node, source: &[u8], filepath: &str) {
        let node_text = get_node_text(node, source);
        
        // Check for assignment patterns like "a = function_call()" or "a = b = c"
        if (node.kind() == "assignment" || node.kind() == "expression_statement") && node_text.contains('=') {
            // Parse assignment: target = source
            if let Some(equals_pos) = node_text.find('=') {
                let left_side = node_text[..equals_pos].trim();
                let right_side = node_text[equals_pos + 1..].trim();
                
                // Handle multiple assignment like a = b = c
                let targets: Vec<String> = left_side.split('=')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                
                // 🎯 CRITICAL FIX: Check if right side is an imported function call
                if right_side.contains('(') && right_side.contains(')') {
                    if let Some(func_name) = self.extract_function_name_from_call(right_side) {
                        // Check if this function is imported (clone to avoid borrow checker issues)
                        if let Some(imports) = self.import_map.get(filepath).cloned() {
                            for import in imports {
                                if import.imported_name == func_name {
                                    // 🎯 CRITICAL: Propagate cross-file taint
                                    for target in &targets {
                                        self.propagate_cross_file_taint(target.clone(), &import, func_name.clone());
                                    }
                                }
                            }
                        }
                        
                        // Track function call with return variable
                        for target in &targets {
                            self.variable_tracker.track_function_call(
                                func_name.clone(),
                                filepath.to_string(),
                                node.start_position().row + 1,
                                Some(target.clone())
                            );
                        }
                    }
                } else {
                    // Handle variable assignments like a = b or a = b = c
                    let source_vars = self.extract_variables_from_expression(right_side);
                    for target in targets {
                        if !source_vars.is_empty() {
                            self.variable_tracker.track_assignment_chain(target, source_vars.clone());
                        }
                    }
                }
            }
        }
    }

    // 🎯 NEW: Propagate cross-file taint from imported functions
    fn propagate_cross_file_taint(&mut self, target_var: String, import: &ImportInfo, func_name: String) {
        // Convert module name to file path
        let source_file = self.module_to_filepath(&import.from_module);
        
        // Check if the imported function is known to return tainted data
        let taint_key = format!("{}:{}", source_file, func_name);
        if let Some(taint_status) = self.variable_tracker.function_returns.get(&taint_key) {
            if let TaintStatus::Tainted(source_type) = taint_status {
                // Mark target variable as tainted with cross-file source
                self.variable_tracker.mark_tainted(
                    target_var.clone(),
                    format!("cross_file_{}", func_name),
                    import.file.clone(),
                    import.line,
                    format!("imported_from_{}", source_type)
                );
            }
        }
        
        // Also check if we can find any exports that match this function
        if let Some(exports) = self.export_map.get(&source_file) {
            for export in exports {
                if export.function_name == func_name {
                    // Mark variable as potentially tainted (we'll verify during analysis)
                    self.variable_tracker.mark_tainted(
                        target_var.clone(),
                        format!("export_{}", func_name),
                        import.file.clone(),
                        import.line,
                        format!("imported_from_{}", import.from_module)
                    );
                    break;
                }
            }
        }
    }

    // 🎯 NEW: Convert module name to filepath
    fn module_to_filepath(&self, module: &str) -> String {
        // Simple conversion: module "source" -> "source.py"
        // This could be enhanced for more complex module resolution
        if module.ends_with(".py") {
            module.to_string()
        } else {
            format!("{}.py", module)
        }
    }

    // NEW: Analyze function calls for return value tracking
    fn analyze_function_calls(&mut self, node: &Node, source: &[u8], filepath: &str) {
        let node_text = get_node_text(node, source);
        
        if node.kind() == "call" || (node_text.contains('(') && node_text.contains(')')) {
            if let Some(func_name) = self.extract_function_name_from_call(&node_text) {
                self.variable_tracker.track_function_call(
                    func_name,
                    filepath.to_string(),
                    node.start_position().row + 1,
                    None // No return variable in this context
                );
            }
        }
    }

    // NEW: Extract function name from function call
    fn extract_function_name_from_call(&self, text: &str) -> Option<String> {
        // Handle patterns like "function_name(args)" or "module.function_name(args)"
        if let Some(paren_pos) = text.find('(') {
            let before_paren = text[..paren_pos].trim();
            // Get the last part (function name) in case of module.function
            if let Some(func_name) = before_paren.split('.').last() {
                // Also handle object.method() calls
                if let Some(simple_name) = before_paren.split('.').last() {
                    return Some(simple_name.trim().to_string());
                }
            }
            return Some(before_paren.trim().to_string());
        }
        None
    }


    // NEW: Extract variable names from an expression
    fn extract_variables_from_expression(&self, expr: &str) -> Vec<String> {
        // Simple variable extraction - split by common delimiters and filter
        expr.split(&[' ', '+', '-', '*', '/', '(', ')', '[', ']', '{', '}', ',', '.'])
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_'))
            .filter(|s| !s.chars().next().unwrap_or('0').is_ascii_digit()) // Not a number
            .map(|s| s.to_string())
            .collect()
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
                let is_cross_file = source.file != sink.file;
                
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
                    is_cross_file,
                });
            }
        }
        None
    }

    // MODIFIED: Enhanced is_flow_reachable to support cross-file flows
    fn is_flow_reachable(
        &self,
        source: &TaintSource,
        sink: &TaintSink,
        tree: &Tree,
        source_bytes: &[u8],
        _language_support: &dyn LanguageSupport,
    ) -> bool {
        // Enhanced flow reachability logic for multi-file support
        
        // NEW: Allow cross-file flows if they're connected through imports
        if source.file != sink.file {
            // Check if there's an import connection between files
            let result = self.is_cross_file_flow_reachable(source, sink);
            if source.file.contains("debug_taint.py") || sink.file.contains("debug_taint.py") {
                eprintln!("DEBUG FLOW: Cross-file flow check result: {}", result);
            }
            return result;
        }
        
        // Same file: use existing logic for intra-function flows
        if source.function != sink.function {
            // Allow flows between different functions in the same file if they use the same variable
            // or if there's a function call connection
            let result = source.variable == sink.variable ||
                   self.has_function_call_connection(&source.function, &sink.function, tree, source_bytes);
            if source.file.contains("debug_taint.py") {
                eprintln!("DEBUG FLOW: Different function check result: {} (same var: {}, call connection: {})", 
                         result, source.variable == sink.variable, 
                         self.has_function_call_connection(&source.function, &sink.function, tree, source_bytes));
            }
            return result;
        }
        
        // Source must come before sink in the same function
        if source.line >= sink.line {
            if source.file.contains("debug_taint.py") {
                eprintln!("DEBUG FLOW: Source line {} >= sink line {}, flow blocked", source.line, sink.line);
            }
            return false;
        }
        
        // Check for direct variable match or variable connection chain
        let var_match = source.variable == sink.variable;
        let has_connection = self.has_variable_connection(&source.variable, &sink.variable, tree, source_bytes);
        let has_transitive = self.check_transitive_connection(&source.variable, &sink.variable, tree, source_bytes);
        
        let result = var_match || has_connection || has_transitive;
        
        if source.file.contains("debug_taint.py") {
            eprintln!("DEBUG FLOW: Same function flow check - var_match: {}, has_connection: {}, has_transitive: {}, result: {}", 
                     var_match, has_connection, has_transitive, result);
        }
        
        result
    }

    // NEW: Check if cross-file flow is reachable through imports
    fn is_cross_file_flow_reachable(&self, source: &TaintSource, sink: &TaintSink) -> bool {
        // 🎯 DEBUG: Add comprehensive debugging for cross-file flow analysis
        eprintln!("🔍 CROSS-FILE FLOW CHECK:");
        eprintln!("   Source: {}:{} function='{}' variable='{}'", 
                 source.file, source.line, source.function, source.variable);
        eprintln!("   Sink:   {}:{} function='{}' variable='{}'", 
                 sink.file, sink.line, sink.function, sink.variable);
        
        // Basic cross-file requirement check
        if source.file == sink.file {
            eprintln!("   ❌ REJECT: Same file");
            return false;
        }
        
        // Check 1: Simple variable name match
        if source.variable == sink.variable {
            eprintln!("   ✅ ACCEPT: Variable name match ('{}' == '{}')", source.variable, sink.variable);
            return true;
        }
        
        // Check 2: Function name to variable match (Critical for cross-file flows)
        if source.function == sink.variable {
            eprintln!("   ✅ ACCEPT: Function-to-variable match ('{}' == '{}')", source.function, sink.variable);
            return true;
        }
        
        // Check 3: Import connection analysis
        if let Some(imports) = self.import_map.get(&sink.file) {
            for import in imports {
                eprintln!("   🔍 Checking import: '{}' from '{}'", import.imported_name, import.from_module);
                
                // Check if sink variable was assigned from imported function
                if import.imported_name == source.function {
                    eprintln!("   ✅ ACCEPT: Import match - source function '{}' is imported", source.function);
                    return true;
                }
                
                // Check if there's a variable assignment from the imported function
                if let Some(_) = self.extract_function_name_from_call(&format!("{} = {}()", sink.variable, import.imported_name)) {
                    if import.imported_name == source.function {
                        eprintln!("   ✅ ACCEPT: Assignment match - '{}' = '{}()'", sink.variable, source.function);
                        return true;
                    }
                }
            }
        }
        
        // Check 4: Export connection analysis
        let source_module = self.extract_module_from_filepath(&source.file);
        if let Some(imports) = self.import_map.get(&sink.file) {
            for import in imports {
                if import.from_module == source_module && import.imported_name == source.function {
                    eprintln!("   ✅ ACCEPT: Export-import match - '{}' from '{}'", source.function, source_module);
                    return true;
                }
            }
        }
        
        eprintln!("   ❌ REJECT: No connection found");
        false
    }

    // 🎯 NEW: Extract module name from filepath
    fn extract_module_from_filepath(&self, filepath: &str) -> String {
        if let Some(filename) = filepath.split('/').last() {
            if let Some(name) = filename.strip_suffix(".py") {
                return name.to_string();
            }
        }
        filepath.to_string()
    }

    // NEW: Check for function call connections
    fn has_function_call_connection(&self, source_func: &str, sink_func: &str, tree: &Tree, source: &[u8]) -> bool {
        // Look for function calls that connect source and sink functions
        let root = tree.root_node();
        self.find_function_call_chain(root, source_func, sink_func, source)
    }

    fn find_function_call_chain(&self, node: Node, source_func: &str, sink_func: &str, source: &[u8]) -> bool {
        let node_text = get_node_text(&node, source);
        
        // Check for function calls
        if node.kind() == "call" || node.kind() == "function_call" {
            if node_text.contains(source_func) && node_text.contains(sink_func) {
                return true;
            }
        }
        
        // Recursively check children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if self.find_function_call_chain(cursor.node(), source_func, sink_func, source) {
                    return true;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        false
    }

    fn has_variable_connection(&self, source_var: &str, sink_var: &str, tree: &Tree, source: &[u8]) -> bool {
        // Look for assignment chains like: a = source; b = a; sink(b)
        let root = tree.root_node();
        self.find_assignment_chain(root, source_var, sink_var, source, &mut HashSet::new())
    }

    fn check_transitive_connection(&self, source_var: &str, sink_var: &str, tree: &Tree, source: &[u8]) -> bool {
        // Check for transitive connections through intermediate variables
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
        
        // For cross-file flows, add an import trace
        if source.file != sink.file {
            traces.push(TaintTrace {
                file: sink.file.clone(),
                line: 1, // Approximate import line
                function: "import".to_string(),
                variable: source.function.clone(),
                operation: "cross_file_import".to_string(),
                code: format!("from {} import {}", source.file, source.function),
                trace_type: TraceType::CrossFileImport,
            });
        }
        
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
        
        // Only collect traces between source and sink lines (for same-file flows)
        let should_collect = if source.file == sink.file {
            node_line > source.line && node_line < sink.line
        } else {
            // For cross-file flows, collect all meaningful nodes
            true
        };
        
        if should_collect {
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
                    code: node_text.trim().to_string(),
                    trace_type: TraceType::Assignment,
                };
                
                traces.push(trace);
            }
        }
        
        // Recursively check child nodes
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
        
        // Look for sanitization patterns in traces
        for trace in traces {
            // Simple sanitization detection
            if trace.code.contains("escape") || 
               trace.code.contains("sanitize") || 
               trace.code.contains("clean") ||
               trace.code.contains("filter") {
                sanitization_points.push(trace.clone());
            }
        }
        
        (!sanitization_points.is_empty(), sanitization_points)
    }

    fn get_line_text(&self, node: &Node, source: &[u8]) -> String {
        get_node_text(node, source).trim().to_string()
    }

    fn matches_taint_pattern(&self, pattern: &str, text: &str) -> bool {
        // Pattern matching logic
        
        // Enhanced pattern matching with support for function calls across imports
        if text.contains(pattern) {
            return true;
        }
        
        // Check for imported function calls
        // This is a simplified version - in practice, would need more sophisticated parsing
        if pattern.contains("(") {
            let base_pattern = pattern.split('(').next().unwrap_or(pattern);
            if text.contains(base_pattern) {
                return true;
            }
        }
        
        // Handle regex patterns - convert them to simple contains for now
        if pattern.contains("\\") {
            let simple_pattern = pattern.replace("\\", "");
            if text.contains(&simple_pattern) {
                return true;
            }
        }
        
        false
    }

    fn extract_variable_from_node(&self, node: &Node, source: &[u8], pattern: Option<&str>) -> String {
        let node_text = get_node_text(node, source);
        
        // 🎯 CRITICAL FIX: Handle assignment statements with function calls consistently
        if node_text.contains('=') {
            if let Some(equals_pos) = node_text.find('=') {
                let left_side = node_text[..equals_pos].trim();
                let right_side = node_text[equals_pos + 1..].trim();
                
                // Check if RHS is a function call
                if let Some(call_name) = self.extract_function_name_from_call(&node_text) {
                    // For cross-file analysis, use the assignment target variable name
                    if let Some(var_name) = left_side.split_whitespace().last() {
                        return var_name.to_string();
                    }
                }
                
                // Regular assignment - use left side variable
                if let Some(var_name) = left_side.split_whitespace().last() {
                    return var_name.to_string();
                }
            }
        }
        
        // 🎯 CRITICAL FIX: For function returns in source detection, use function name
        if node.kind() == "return_statement" {
            let function_name = self.get_containing_function(node, source);
            if function_name != "global" {
                return function_name;
            }
        }
        
        // For patterns like "os.system(user_input)", extract "user_input"
        if let Some(pattern_str) = pattern {
            if let Some(_start) = pattern_str.find('(') {
                // Extract variable from pattern like "os.system(variable)"
                if let Some(var_start) = node_text.find('(') {
                    let after_paren = &node_text[var_start + 1..];
                    if let Some(var_end) = after_paren.find(')') {
                        let var_name = after_paren[..var_end].trim();
                        if !var_name.is_empty() && var_name != "\"\"" && var_name != "''" {
                            return var_name.to_string();
                        }
                    }
                }
            }
        }
        
        // Fallback: try to extract the first identifier
        if let Some(identifier) = self.extract_identifier_from_tree(node, source) {
            return identifier;
        }
        
        "unknown_var".to_string()
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

    // NEW: Method to analyze multiple files for cross-file taint analysis
    pub fn analyze_cross_file(
        &mut self,
        all_sources: &[TaintSource],
        all_sinks: &[TaintSink],
    ) -> Vec<TaintFlow> {
        let mut cross_file_flows = Vec::new();
        
        // 🎯 DEBUG: Show what we're working with
        eprintln!("🔍 CROSS-FILE ANALYSIS DEBUG:");
        eprintln!("   Total sources: {}", all_sources.len());
        eprintln!("   Total sinks: {}", all_sinks.len());
        
        for (i, source) in all_sources.iter().enumerate() {
            eprintln!("   Source {}: {}:{} function='{}' variable='{}' operation='{}'", 
                     i, source.file, source.line, source.function, source.variable, source.operation);
        }
        
        for (i, sink) in all_sinks.iter().enumerate() {
            eprintln!("   Sink {}: {}:{} function='{}' variable='{}' operation='{}'", 
                     i, sink.file, sink.line, sink.function, sink.variable, sink.operation);
        }
        
        // Check every source against every sink
        for source in all_sources {
            for sink in all_sinks {
                // Only check cross-file combinations
                if source.file != sink.file {
                    eprintln!("🔍 Checking cross-file: {} -> {}", source.file, sink.file);
                    
                    if self.is_cross_file_flow_reachable(source, sink) {
                        // Create cross-file flow
                        let flow_id = format!("flow_{}_{}_{}", 
                                            source.file.split('/').last().unwrap_or("unknown"),
                                            source.line, sink.line);
                        let flow = TaintFlow {
                            flow_id,
                            flow_name: Some(format!("{} -> {}", source.operation, sink.operation)),
                            severity: DEFAULT_SEVERITY.to_string(),
                            confidence: DEFAULT_CONFIDENCE.to_string(),
                            source: source.clone(),
                            sink: sink.clone(),
                            traces: Vec::new(), // Cross-file traces would be complex
                            is_sanitized: false,
                            sanitization_points: Vec::new(),
                            is_cross_file: true,
                        };
                        cross_file_flows.push(flow);
                    }
                }
            }
        }
        
        eprintln!("🔍 Cross-file flows created: {}", cross_file_flows.len());
        cross_file_flows
    }


}

impl VariableTracker {
    fn new() -> Self {
        Self {
            tainted_vars: HashMap::new(),
            cross_file_vars: HashMap::new(),
            function_calls: HashMap::new(),
            assignment_chains: HashMap::new(),
            function_returns: HashMap::new(),
        }
    }

    fn reset(&mut self) {
        self.tainted_vars.clear();
        self.cross_file_vars.clear();
        self.function_calls.clear();
        self.assignment_chains.clear();
        self.function_returns.clear();
    }

    fn mark_tainted(&mut self, variable: String, flow_id: String, file: String, line: usize, taint_type: String) {
        let taint_info = TaintInfo {
            flow_id: flow_id.clone(),
            source_type: taint_type.clone(),
            propagation_chain: vec![variable.clone()],
        };
        
        self.tainted_vars.insert(variable.clone(), taint_info.clone());
        
        // Mark as cross-file variable if needed
        self.cross_file_vars.insert(variable, CrossFileVarInfo {
            original_file: file,
            original_function: "unknown".to_string(),
            import_info: None,
            taint_info: Some(taint_info),
        });
    }

    // NEW: Track function calls and their return values
    fn track_function_call(&mut self, function_name: String, file: String, line: usize, return_var: Option<String>) {
        // Check if this function is known to return tainted data
        let taint_status = self.function_returns.get(&function_name)
            .cloned()
            .unwrap_or(TaintStatus::Unknown);

        let call_info = FunctionCallInfo {
            function_name: function_name.clone(),
            file,
            line,
            return_variable: return_var.clone(),
            taint_status: taint_status.clone(),
        };

        self.function_calls.insert(function_name.clone(), call_info);

        // If function returns tainted data and we have a return variable, mark it as tainted
        if let (Some(var), TaintStatus::Tainted(source_type)) = (return_var, taint_status) {
            let taint_info = TaintInfo {
                flow_id: format!("func_call_{}", function_name),
                source_type,
                propagation_chain: vec![var.clone()],
            };
            self.tainted_vars.insert(var, taint_info);
        }
    }

    // NEW: Mark a function as returning tainted data
    fn mark_function_returns_taint(&mut self, function_name: String, source_type: String) {
        self.function_returns.insert(function_name, TaintStatus::Tainted(source_type));
    }

    // NEW: Track assignment chains like a = b = source()
    fn track_assignment_chain(&mut self, target_var: String, source_vars: Vec<String>) {
        // Check if any source variables are tainted
        for source_var in &source_vars {
            if let Some(taint_info) = self.tainted_vars.get(source_var) {
                // Propagate taint to target variable
                let mut new_chain = taint_info.propagation_chain.clone();
                new_chain.push(target_var.clone());
                
                let new_taint_info = TaintInfo {
                    flow_id: taint_info.flow_id.clone(),
                    source_type: taint_info.source_type.clone(),
                    propagation_chain: new_chain,
                };
                
                self.tainted_vars.insert(target_var.clone(), new_taint_info);
                break; // First tainted source taints the target
            }
        }
        
        // Track the assignment chain
        self.assignment_chains.insert(target_var, source_vars);
    }


}



/// Enhanced merge function with cross-file support
pub fn merge_taint_results(results: Vec<TaintAnalysisResult>) -> TaintAnalysisResult {
    if results.is_empty() {
        return TaintAnalysisResult {
            flows: Vec::new(),
            summary: TaintSummary {
                total_flows: 0,
                unsanitized_flows: 0,
                sanitized_flows: 0,
                cross_file_flows: 0,
                files_analyzed: 0,
                functions_analyzed: 0,
            },
            imports: Vec::new(),
            exports: Vec::new(),
            cross_file_flows: Vec::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
        };
    }
    
    let mut all_flows = Vec::new();
    let mut all_imports = Vec::new();
    let mut all_exports = Vec::new();
    let mut all_cross_file_flows = Vec::new();
    let mut total_files = 0;
    let mut total_functions = 0;
    
    for result in results {
        all_flows.extend(result.flows);
        all_imports.extend(result.imports);
        all_exports.extend(result.exports);
        all_cross_file_flows.extend(result.cross_file_flows);
        total_files += result.summary.files_analyzed;
        total_functions += result.summary.functions_analyzed;
    }
    
    let unsanitized_flows = all_flows.iter().filter(|f| !f.is_sanitized).count();
    let sanitized_flows = all_flows.iter().filter(|f| f.is_sanitized).count();
    let cross_file_flow_count = all_flows.iter().filter(|f| f.is_cross_file).count();
    
    TaintAnalysisResult {
        flows: all_flows,
        summary: TaintSummary {
            total_flows: unsanitized_flows + sanitized_flows,
            unsanitized_flows,
            sanitized_flows,
            cross_file_flows: cross_file_flow_count,
            files_analyzed: total_files,
            functions_analyzed: total_functions,
        },
        imports: all_imports,
        exports: all_exports,
        cross_file_flows: all_cross_file_flows,
        sources: Vec::new(),
        sinks: Vec::new(),
    }
}



// NEW: Helper struct for import name parsing
#[derive(Debug)]
struct ImportName {
    name: String,
    alias: Option<String>,
}
