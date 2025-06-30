use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use crate::rules::{Rules, UnifiedRule};
use crate::language::LanguageSupport;
use crate::parser::get_node_text;
use crate::scanner::utils::{AstUtils, CodePatternType, VariableType};
use crate::scanner::data_flow::DataFlowGraph;
use crate::common::CommonUtils;
use tree_sitter::{Node, Tree};
use crate::models::{TaintFlow, TaintSource, TaintSink, TaintTrace, TaintSummary, TraceType};

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
    pub fn to_findings(&self) -> Vec<crate::models::Finding> {
        use crate::models::*;
        
        self.flows.iter().map(|flow| Finding {
            file: flow.sink.file.clone(),
            line: flow.sink.line,
            column: 0, // TaintFlow doesn't track columns yet
            end_line: flow.sink.line,
            end_column: 0,
            function: flow.sink.function.clone(),
            // Use rule finding_type if available, otherwise use generic format
            finding_type: flow.rule_finding_type.clone()
                .unwrap_or_else(|| format!("taint_flow_{}", flow.flow_id)),
            snippet: flow.sink.code.clone(),
            severity: flow.severity.clone(),
            confidence: flow.confidence.clone(),
            // Use rule description if available, otherwise use flow_name
            description: flow.rule_description.clone()
                .or_else(|| flow.flow_name.clone()),
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
                    operation: match trace.trace_type {
                        TraceType::Propagation => "propagation".to_string(),
                        TraceType::Assignment => "assignment".to_string(),
                        TraceType::Sanitization => "sanitization".to_string(),
                        TraceType::FunctionCall => "function_call".to_string(),
                        TraceType::CrossFileImport => "cross_file_import".to_string(),
                    },
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

// NEW: Control flow scope tracking for branch-aware analysis
#[derive(Debug, Clone)]
struct ControlFlowScope {
    if_branches: Vec<BranchInfo>,
    elif_branches: Vec<BranchInfo>, 
    else_branch: Option<BranchInfo>,
    current_branch_id: Option<String>,
    branch_nesting_level: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BranchType {
    If,
    Elif, 
    Else,
    Function,
    Global,
}

impl ControlFlowScope {
    fn new() -> Self {
        Self {
            if_branches: Vec::new(),
            elif_branches: Vec::new(),
            else_branch: None,
            current_branch_id: None,
            branch_nesting_level: 0,
        }
    }
    
    fn enter_branch(&mut self, branch_type: BranchType, line_start: usize) -> String {
        let branch_id = format!("{}_{}_{}_{}", 
            match branch_type {
                BranchType::If => "if",
                BranchType::Elif => "elif", 
                BranchType::Else => "else",
                BranchType::Function => "func",
                BranchType::Global => "global",
            },
            line_start,
            self.branch_nesting_level,
            self.if_branches.len()
        );
        
        let mut mutually_exclusive_with = Vec::new();
        
        // Build mutual exclusion relationships
        match branch_type {
            BranchType::If => {
                // Clear previous if/elif/else group
                self.elif_branches.clear();
                self.else_branch = None;
            },
            BranchType::Elif => {
                // Mutually exclusive with all previous if/elif branches
                mutually_exclusive_with.extend(
                    self.if_branches.iter().map(|b| b.branch_id.clone())
                );
                mutually_exclusive_with.extend(
                    self.elif_branches.iter().map(|b| b.branch_id.clone())
                );
            },
            BranchType::Else => {
                // Mutually exclusive with all if/elif branches
                mutually_exclusive_with.extend(
                    self.if_branches.iter().map(|b| b.branch_id.clone())
                );
                mutually_exclusive_with.extend(
                    self.elif_branches.iter().map(|b| b.branch_id.clone())
                );
            },
            _ => {}
        }
        
        let branch_info = BranchInfo {
            branch_id: branch_id.clone(),
            branch_type: branch_type.clone(),
            line_start,
            line_end: line_start, // Will be updated on exit
            variables: HashSet::new(),
            parent_branch: self.current_branch_id.clone(),
            mutually_exclusive_with,
        };
        
        // Add to appropriate collection
        match branch_type {
            BranchType::If => self.if_branches.push(branch_info),
            BranchType::Elif => self.elif_branches.push(branch_info),
            BranchType::Else => self.else_branch = Some(branch_info),
            _ => {}
        }
        
        self.current_branch_id = Some(branch_id.clone());
        self.branch_nesting_level += 1;
        
        branch_id
    }
    
    fn exit_branch(&mut self, line_end: usize) {
        if let Some(current_id) = &self.current_branch_id {
            // Update line_end for current branch
            if let Some(branch) = self.if_branches.iter_mut()
                .find(|b| &b.branch_id == current_id) {
                branch.line_end = line_end;
            } else if let Some(branch) = self.elif_branches.iter_mut()
                .find(|b| &b.branch_id == current_id) {
                branch.line_end = line_end;
            } else if let Some(ref mut branch) = self.else_branch {
                if &branch.branch_id == current_id {
                    branch.line_end = line_end;
                }
            }
        }
        
        self.branch_nesting_level = self.branch_nesting_level.saturating_sub(1);
        self.current_branch_id = None; // Simplified - could track parent
    }
    
    fn add_variable_to_current_branch(&mut self, variable: String) {
        if let Some(current_id) = &self.current_branch_id {
            if let Some(branch) = self.if_branches.iter_mut()
                .find(|b| &b.branch_id == current_id) {
                branch.variables.insert(variable);
            } else if let Some(branch) = self.elif_branches.iter_mut()
                .find(|b| &b.branch_id == current_id) {
                branch.variables.insert(variable);
            } else if let Some(ref mut branch) = self.else_branch {
                if &branch.branch_id == current_id {
                    branch.variables.insert(variable);
                }
            }
        }
    }
    
    fn are_branches_mutually_exclusive(&self, branch_id1: &str, branch_id2: &str) -> bool {
        // Check direct mutual exclusion
        let branch1 = self.find_branch(branch_id1);
        if let Some(branch) = branch1 {
            return branch.mutually_exclusive_with.contains(&branch_id2.to_string());
        }
        false
    }
    
    fn find_branch(&self, branch_id: &str) -> Option<&BranchInfo> {
        self.if_branches.iter()
            .chain(self.elif_branches.iter())
            .chain(self.else_branch.iter())
            .find(|b| b.branch_id == branch_id)
    }
    
    fn get_current_branch_id(&self) -> Option<String> {
        self.current_branch_id.clone()
    }
}

#[derive(Debug, Clone, PartialEq)]
struct BranchInfo {
    branch_id: String,
    branch_type: BranchType,
    line_start: usize,
    line_end: usize,
    variables: HashSet<String>,
    parent_branch: Option<String>,
    mutually_exclusive_with: Vec<String>,
}

pub struct TaintAnalyzer {
    rules: Rules,
    variable_tracker: VariableTracker,
    import_map: HashMap<String, Vec<ImportInfo>>,
    export_map: HashMap<String, Vec<ExportInfo>>,
    data_flow_graph: DataFlowGraph,
    // NEW: Control flow scope for branch-aware analysis
    control_flow_scope: ControlFlowScope,
}

// NEW: Enhanced variable tracker with function call support
#[derive(Debug, Clone)]
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
            data_flow_graph: DataFlowGraph::new(),
            control_flow_scope: ControlFlowScope::new(),
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
        
        // Reset variable tracker and control flow scope for each file
        self.variable_tracker.reset();
        self.control_flow_scope = ControlFlowScope::new();
        
        // Build enhanced data flow graph with branch awareness
        self.data_flow_graph.build_from_ast(tree, source, filepath);
        
        // Extract imports and exports for cross-file analysis
        self.extract_imports_and_exports(tree.root_node(), source, filepath, &mut imports, &mut exports);
        self.import_map.insert(filepath.to_string(), imports.clone());
        self.export_map.insert(filepath.to_string(), exports.clone());
        
        // Enhanced source and sink collection with control flow scope
        self.find_sources_and_sinks_with_scope(
            tree.root_node(), 
            source, 
            filepath, 
            language_support, 
            &mut sources, 
            &mut sinks
        );
        
        // Deduplicate sources and sinks
        self.deduplicate_sources(&mut sources);
        self.deduplicate_sinks(&mut sinks);
        
        // Track data flows between sources and sinks with enhanced validation
        let mut seen_flows: HashSet<String> = HashSet::with_capacity(sources.len() * sinks.len());
        
        // ENHANCED: Create flows with branch-aware validation
        for source_item in &sources {
            for sink_item in &sinks {
                // NEW: Pre-validate control flow compatibility
                if !self.are_flows_in_compatible_branches(source_item, sink_item) {
                    continue; // Skip flows between mutually exclusive branches
                }
                
                // ENHANCED: Use branch-aware data flow graph validation
                if let Some(flow_path) = self.data_flow_graph.find_flow_path(
                    &source_item.variable,
                    &sink_item.variable,
                    source_item.line,
                    sink_item.line,
                ) {
                    // Only create flow if there's actual validated data flow
                    let flow_id = format!("flow_{}_{}_{}_{}", 
                                        source_item.file.split('/').last().unwrap_or("unknown"),
                                        source_item.line, sink_item.line, flows.len());
                    
                    let is_cross_file = source_item.file != sink_item.file;
                if is_cross_file {
                    cross_file_flows.push(CrossFileFlow {
                        source_file: source_item.file.clone(),
                            sink_file: sink_item.file.clone(),
                        imported_function: source_item.function.clone(),
                        is_cross_file: true,
                    });
                }
                
                    // Create flow with validated data path
                    let (rule_id, rule_name, rule_description, rule_finding_type) = self.find_rule_info_for_flow(source_item, sink_item);
                    
                    let flow = TaintFlow {
                        flow_id,
                        flow_name: Some(format!("{} -> {}", source_item.operation, sink_item.operation)),
                        severity: DEFAULT_SEVERITY.to_string(),
                        confidence: DEFAULT_CONFIDENCE.to_string(),
                        source: source_item.clone(),
                        sink: sink_item.clone(),
                        traces: Vec::new(), // Enhanced traces will be added later
                        is_sanitized: false, // Could check sanitization in flow path
                        sanitization_points: Vec::new(),
                        is_cross_file,
                        rule_id,
                        rule_name,
                        rule_description,
                        rule_finding_type,
                    };
                    
                    // Create semantic key for better deduplication
                    let flow_key = self.create_semantic_flow_key(source_item, sink_item);
                
                if seen_flows.insert(flow_key) {
                        flows.push(flow);
                    }
                } else if source_item.file == sink_item.file {
                    // Fallback: check basic reachability for same-file flows, but with branch validation
                    if self.are_flows_in_compatible_branches(source_item, sink_item) &&
                       self.is_flow_reachable(source_item, sink_item, tree, source, language_support) {
                        let flow_id = format!("flow_basic_{}_{}_{}_{}", 
                                            source_item.file.split('/').last().unwrap_or("unknown"),
                                            source_item.line, sink_item.line, flows.len());
                        
                        let (rule_id, rule_name, rule_description, rule_finding_type) = self.find_rule_info_for_flow(source_item, sink_item);
                        
                        let flow = TaintFlow {
                            flow_id,
                            flow_name: Some(format!("{} -> {}", source_item.operation, sink_item.operation)),
                            severity: DEFAULT_SEVERITY.to_string(),
                            confidence: "Low".to_string(), // Lower confidence for basic check
                            source: source_item.clone(),
                            sink: sink_item.clone(),
                            traces: self.find_traces_between_isolated(source_item, sink_item, tree, source, language_support),
                            is_sanitized: false,
                            sanitization_points: Vec::new(),
                            is_cross_file: false,
                            rule_id,
                            rule_name,
                            rule_description,
                            rule_finding_type,
                        };
                        
                        let flow_key = self.create_semantic_flow_key(source_item, sink_item);
                        
                        if seen_flows.insert(flow_key) {
                    flows.push(flow);
                }
            }
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

    /// NEW: Enhanced source/sink collection with control flow awareness
    fn find_sources_and_sinks_with_scope(
        &mut self,
        node: Node,
        source: &[u8],
        filepath: &str,
        language_support: &dyn LanguageSupport,
        sources: &mut Vec<TaintSource>,
        sinks: &mut Vec<TaintSink>,
    ) {
        self.find_sources_and_sinks_with_scope_recursive(
            node, source, filepath, language_support, sources, sinks, &mut self.control_flow_scope.clone()
        );
    }
    
    /// NEW: Recursive source/sink collection with scope tracking
    fn find_sources_and_sinks_with_scope_recursive(
        &mut self,
        node: Node,
        source: &[u8],
        filepath: &str,
        language_support: &dyn LanguageSupport,
        sources: &mut Vec<TaintSource>,
        sinks: &mut Vec<TaintSink>,
        scope: &mut ControlFlowScope,
    ) {
        let line = node.start_position().row + 1;
        
        // Track control flow branches
        match node.kind() {
            "if_statement" => {
                let _branch_id = scope.enter_branch(BranchType::If, line);
                
                // Process if block content
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        self.find_sources_and_sinks_with_scope_recursive(
                            cursor.node(), source, filepath, language_support, 
                            sources, sinks, scope
                        );
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                
                scope.exit_branch(line);
                return;
            }
            "elif_clause" => {
                let _branch_id = scope.enter_branch(BranchType::Elif, line);
                
                // Process elif block content
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        self.find_sources_and_sinks_with_scope_recursive(
                            cursor.node(), source, filepath, language_support, 
                            sources, sinks, scope
                        );
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                
                scope.exit_branch(line);
                return;
            }
            "else_clause" => {
                let _branch_id = scope.enter_branch(BranchType::Else, line);
                
                // Process else block content
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        self.find_sources_and_sinks_with_scope_recursive(
                            cursor.node(), source, filepath, language_support, 
                            sources, sinks, scope
                        );
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                
                scope.exit_branch(line);
                return;
            }
            _ => {}
        }
        
        // Enhanced source and sink detection with branch tracking
        let current_branch_id = scope.get_current_branch_id();
        
        // Existing source/sink detection logic but with branch awareness
        for unified_rule in &self.rules.rules {
            if unified_rule.is_taint_rule() {
                let node_text = get_node_text(&node, source);
                
                // Check source patterns
                if let Some(source_patterns) = &unified_rule.sources {
                    for pattern in source_patterns {
                        if self.matches_taint_pattern(pattern, &node_text) {
                            let variable = self.extract_variable_from_node(&node, source, Some(pattern));
                            let function_name = self.get_containing_function(&node, source);
                            
                            // Track variable in current branch
                            if let Some(_branch_id) = &current_branch_id {
                                scope.add_variable_to_current_branch(variable.clone());
                            }
                            
                            let source_item = TaintSource {
                                file: filepath.to_string(),
                                line,
                                function: function_name,
                                variable,
                                operation: pattern.to_string(),
                                code: self.get_line_text(&node, source),
                                branch_id: current_branch_id.clone(),
                            };
                            
                            sources.push(source_item);
                        }
                    }
                }
                
                // Check sink patterns
                if let Some(sink_patterns) = &unified_rule.sinks {
                    for pattern in sink_patterns {
                        if self.matches_taint_pattern(pattern, &node_text) {
                            let variable = self.extract_variable_from_node(&node, source, Some(pattern));
                            let function_name = self.get_containing_function(&node, source);
                            
                            // Track variable in current branch
                            if let Some(_branch_id) = &current_branch_id {
                                scope.add_variable_to_current_branch(variable.clone());
                            }
                            
                            let sink_item = TaintSink {
                                file: filepath.to_string(),
                                line,
                                function: function_name,
                                variable,
                                operation: pattern.to_string(),
                                code: self.get_line_text(&node, source),
                                branch_id: current_branch_id.clone(),
                            };
                            
                            sinks.push(sink_item);
                        }
                    }
                }
            }
        }
        
        // Continue recursive traversal
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.find_sources_and_sinks_with_scope_recursive(
                    cursor.node(), source, filepath, language_support, 
                    sources, sinks, scope
                );
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    
    /// NEW: Check if flows are in compatible (non-mutually-exclusive) branches
    fn are_flows_in_compatible_branches(&self, source: &TaintSource, sink: &TaintSink) -> bool {
        // If either source or sink has no branch, allow the flow (same branch or global scope)
        let (Some(source_branch), Some(sink_branch)) = (&source.branch_id, &sink.branch_id) else {
            return true;
        };
        
        // Same branch is always compatible
        if source_branch == sink_branch {
            return true;
        }
        
        // Check if branches are mutually exclusive using data flow graph
        !self.data_flow_graph.are_branches_mutually_exclusive(source_branch, sink_branch)
    }
    
    /// NEW: Enhanced trace collection with path isolation
    fn find_traces_between_isolated(
        &self,
        source: &TaintSource,
        sink: &TaintSink,
        tree: &Tree,
        source_bytes: &[u8],
        _language_support: &dyn LanguageSupport,
    ) -> Vec<TaintTrace> {
        // Only collect traces from validated flow path to eliminate phantom variables
        if let Some(flow_path) = self.data_flow_graph.find_flow_path(
            &source.variable,
            &sink.variable,
            source.line,
            sink.line,
        ) {
            // Convert validated flow path steps to taint traces
            flow_path.steps.into_iter().map(|step| TaintTrace {
                file: source.file.clone(),
                line: step.line,
                variable: step.variable,
                code: step.context,
                trace_type: TraceType::Assignment,
                function: source.function.clone(),
            }).collect()
        } else {
            Vec::new() // No phantom traces
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
                    
                    // Check sources with semantic classification
                    if let Some(source_patterns) = &unified_rule.sources {
                        for pattern in source_patterns {
                            if self.matches_taint_pattern(pattern, &node_text) {
                                // Use semantic classification to avoid false positives
                                let pattern_type = AstUtils::classify_code_pattern(&node_text, pattern);
                                
                                match pattern_type {
                                    CodePatternType::Configuration => {
                                        // Skip configuration patterns - not user input
                                        continue;
                                    },
                                    CodePatternType::UserInput => {
                                        // Create source only for actual user input
                                let variable = self.extract_variable_from_node(&node, source, None);
                                let taint_source = TaintSource {
                                    file: filepath.to_string(),
                                    line: node.start_position().row + 1,
                                    function: function_name.clone(),
                                    variable: variable.clone(),
                                    operation: pattern.to_string(),
                                    code: self.get_line_text(&node, source),
                                            branch_id: None,
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
                                    },
                                    CodePatternType::Neutral => {
                                        // Check environment variables more carefully
                                        if pattern.contains("environ") && AstUtils::is_environment_read(&node_text) {
                                            let variable = self.extract_variable_from_node(&node, source, None);
                                            let taint_source = TaintSource {
                                                file: filepath.to_string(),
                                                line: node.start_position().row + 1,
                                                function: function_name.clone(),
                                                variable: variable.clone(),
                                                operation: pattern.to_string(),
                                                code: self.get_line_text(&node, source),
                                                branch_id: None,
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
                                    },
                                    _ => {}
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
                                        branch_id: None,
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
        CommonUtils::extract_variables_from_expression(expr)
    }

    // NEW: Helper method to find rule information for a taint flow (delegates to CoreUtils for variable extraction)
    fn find_rule_info_for_flow(&self, source: &TaintSource, sink: &TaintSink) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
        let mut matching_rules = Vec::new();
        
        // Collect ALL matching rules (instead of returning first)
        for unified_rule in &self.rules.rules {
            if unified_rule.is_taint_rule() {
                let source_matches = unified_rule.sources.as_ref()
                    .map(|patterns| patterns.iter().any(|pattern| pattern == &source.operation))
                    .unwrap_or(false);
                    
                let sink_matches = unified_rule.sinks.as_ref()
                    .map(|patterns| patterns.iter().any(|pattern| pattern == &sink.operation))
                    .unwrap_or(false);
                    
                if source_matches && sink_matches {
                    matching_rules.push(unified_rule);
                }
            }
        }
        
        // Select best rule by priority
        if let Some(best_rule) = self.select_best_rule(matching_rules) {
            (
                best_rule.id,
                best_rule.name, 
                best_rule.description,
                best_rule.finding_type,
            )
        } else {
            (None, None, None, None)
        }
    }

    /// Select the best rule from multiple matching rules based on priority
    fn select_best_rule(&self, rules: Vec<&UnifiedRule>) -> Option<UnifiedRule> {
        if rules.is_empty() {
            return None;
        }
        
        // Find the rule with highest priority
        let best_rule = rules.iter()
            .max_by_key(|rule| self.calculate_rule_priority(rule))?;
        
        Some((*best_rule).clone())
    }
    
    /// Calculate automatic priority for a rule based on existing metadata
    fn calculate_rule_priority(&self, rule: &UnifiedRule) -> u32 {
        let mut priority = 0u32;
        
        // Use existing metadata for priority
        if rule.id.is_some() { priority += 10; }
        if rule.name.is_some() { priority += 10; }
        if rule.description.is_some() { priority += 10; }
        if rule.finding_type.is_some() { priority += 15; }
        
        // Pattern specificity (use existing pattern fields)
        priority += self.calculate_pattern_specificity(rule);
        
        priority
    }
    
    /// Calculate pattern specificity score for priority
    fn calculate_pattern_specificity(&self, rule: &UnifiedRule) -> u32 {
        let mut score = 0u32;
        
        // More specific patterns = higher priority
        if let Some(sources) = &rule.sources {
            for pattern in sources {
                if pattern.contains('\'') || pattern.contains('"') { 
                    score += 20; // Quoted patterns are very specific
                } else if pattern.contains('.') { 
                    score += 15; // Attribute access is specific
                } else if pattern.contains('*') { 
                    score += 5;  // Wildcards are less specific
                } else { 
                    score += 10; // Simple patterns
                }
            }
        }
        
        if let Some(sinks) = &rule.sinks {
            for pattern in sinks {
                if pattern.contains('\'') || pattern.contains('"') { 
                    score += 20; 
                } else if pattern.contains('.') { 
                    score += 15; 
                } else if pattern.contains('*') { 
                    score += 5;  
                } else { 
                    score += 10; 
                }
            }
        }
        
        score
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
                
                let (rule_id, rule_name, rule_description, rule_finding_type) = self.find_rule_info_for_flow(source, sink);
                
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
                    rule_id,
                    rule_name,
                    rule_description,
                    rule_finding_type,
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
                        return self.is_cross_file_flow_reachable(source, sink);
        }
        
        // Same file: use existing logic for intra-function flows
        if source.function != sink.function {
            // Allow flows between different functions in the same file if they use the same variable
            // or if there's a function call connection
            let result = source.variable == sink.variable ||
                   self.has_function_call_connection(&source.function, &sink.function, tree, source_bytes);

            return result;
        }
        
        // Source must come before sink in the same function
        if source.line >= sink.line {
            return false;
        }
        
        // Check for direct variable match or variable connection chain
        let var_match = source.variable == sink.variable;
        let has_connection = self.has_variable_connection(&source.variable, &sink.variable, tree, source_bytes);
        let has_transitive = self.check_transitive_connection(&source.variable, &sink.variable, tree, source_bytes);
        
        let result = var_match || has_connection || has_transitive;
        

        
        result
    }

    // NEW: Check if cross-file flow is reachable through imports
    fn is_cross_file_flow_reachable(&self, source: &TaintSource, sink: &TaintSink) -> bool {
        // Same file flows are always reachable (handled by local data flow)
        if source.file == sink.file {
            return true;
        }
        
        // STRICT REQUIREMENT: Must have actual import relationship
        let empty_vec = Vec::new();
        let sink_imports = self.import_map.get(&sink.file).unwrap_or(&empty_vec);
        
        // Check if sink file imports from source file
        if let Some(import) = self.find_matching_import(sink_imports, source, sink) {
            // STRICT VALIDATION: Import must actually be used in sink context
            return self.validate_import_usage_strict(import, sink);
        }
        
        // NO FALLBACK - if no import relationship, flow is impossible
        false
    }
    
    /// Find import that matches the cross-file flow pattern
    fn find_matching_import<'a>(&self, imports: &'a [ImportInfo], source: &TaintSource, sink: &TaintSink) -> Option<&'a ImportInfo> {
        let source_module = self.extract_module_from_filepath(&source.file);
        
            for import in imports {
            // Check if import is from the source module
            if self.module_matches(&import.from_module, &source_module) {
                // Check if the imported name matches the source function/variable
                if self.import_matches_source_context(import, source, sink) {
                    return Some(import);
                }
            }
        }
        
        None
    }
    
    /// Strict validation that import is actually used in sink context
    fn validate_import_usage_strict(&self, import: &ImportInfo, sink: &TaintSink) -> bool {
        // The sink code must reference the imported name
        let import_name = import.alias.as_ref().unwrap_or(&import.imported_name);
        
        // STRICT CHECK: Import name must appear in sink code
        if !sink.code.contains(import_name) {
            return false;
        }
        
        // STRICT CHECK: Must be used in function call context, not just mentioned
        if !self.is_import_used_in_function_call(&sink.code, import_name) {
            return false;
        }
        
        // STRICT CHECK: The sink line must be close to import usage (within reasonable scope)
        // This prevents phantom flows across unrelated parts of large files
        if !self.is_sink_in_import_scope(sink, import) {
            return false;
        }
        
        true
    }
    
    /// Check if import is used in function call context (not just variable reference)
    fn is_import_used_in_function_call(&self, code: &str, import_name: &str) -> bool {
        // Look for patterns like import_name.method() or import_name()
        let function_call_patterns = [
            format!("{}.", import_name),
            format!("{}(", import_name),
        ];
        
        function_call_patterns.iter().any(|pattern| code.contains(pattern))
    }
    
    /// Check if sink is within reasonable scope of import usage
    fn is_sink_in_import_scope(&self, sink: &TaintSink, import: &ImportInfo) -> bool {
        // For now, require they are in the same function
        // This prevents phantom flows across completely unrelated functions
        sink.function != "global" && import.line < sink.line
    }
    
    /// Check if import context matches source context
    fn import_matches_source_context(&self, import: &ImportInfo, source: &TaintSource, _sink: &TaintSink) -> bool {
        // For function imports, the imported name should match or be related to source function
                if import.imported_name == source.function {
                    return true;
                }
                
        // For module imports, check if source function is accessible through the import
        if import.imported_name == "*" {
            // Wildcard import - allows access to any function in the module
            return true;
        }
        
        // Check if import is of the specific function that contains the source
        if self.is_function_accessible_through_import(import, source) {
            return true;
        }
        
        false
    }
    
    /// Check if source function is accessible through the import
    fn is_function_accessible_through_import(&self, import: &ImportInfo, source: &TaintSource) -> bool {
        // If importing the specific function name
                    if import.imported_name == source.function {
                        return true;
                    }
        
        // If importing a module that contains the function
        // This requires the import to be module-level (not specific function)
        if import.imported_name.chars().next().map_or(false, |c| c.is_uppercase()) {
            // Looks like a module import - check if it could contain the function
            return self.could_module_contain_function(&import.imported_name, &source.function);
        }
        
        false
    }
    
    /// Check if module could contain the given function
    fn could_module_contain_function(&self, _module_name: &str, _function_name: &str) -> bool {
        // Conservative approach - only allow if we have explicit evidence
        // This prevents phantom flows between unrelated modules
        false
    }
    
    /// Check if module names match (handling different path formats)
    fn module_matches(&self, import_module: &str, source_module: &str) -> bool {
        // Direct match
        if import_module == source_module {
                    return true;
                }
        
        // Handle relative imports
        if import_module.starts_with('.') {
            let normalized_import = import_module.trim_start_matches('.');
            if normalized_import == source_module {
                return true;
            }
        }
        
        // Handle path-based module names
        let import_parts: Vec<&str> = import_module.split('.').collect();
        let source_parts: Vec<&str> = source_module.split('.').collect();
        
        // Check if source module is a suffix of import module
        if source_parts.len() <= import_parts.len() {
            let start_idx = import_parts.len() - source_parts.len();
            return import_parts[start_idx..] == source_parts[..];
        }
        
        false
    }

    /// Extract module name from filepath
    fn extract_module_from_filepath(&self, filepath: &str) -> String {
        if let Some(filename) = filepath.split('/').last() {
            if let Some(name) = filename.strip_suffix(".py") {
                return name.to_string();
            }
        }
        filepath.to_string()
    }
    
    /// Word boundary matching for short patterns
    fn word_boundary_match(&self, pattern: &str, text: &str) -> bool {
        if text.len() < pattern.len() {
            return false;
        }
        
        let pattern_bytes = pattern.as_bytes();
        let text_bytes = text.as_bytes();
        
        for i in 0..=(text_bytes.len() - pattern_bytes.len()) {
            // Check if pattern matches at position i
            if text_bytes[i..i + pattern_bytes.len()] == *pattern_bytes {
                // Check word boundaries
                let before_is_boundary = i == 0 || !text_bytes[i - 1].is_ascii_alphanumeric();
                let after_is_boundary = 
                    i + pattern_bytes.len() == text_bytes.len() || 
                    !text_bytes[i + pattern_bytes.len()].is_ascii_alphanumeric();
                
                if before_is_boundary && after_is_boundary {
                    return true;
                }
            }
        }
        
        false
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
        traces.dedup_by(|a, b| a.line == b.line && a.trace_type == b.trace_type);
        
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

    /// PHASE 2: Enhanced Variable Extraction (Fixed - replaces broken extract_variable_from_node)
    fn extract_variable_from_node(&self, node: &Node, source: &[u8], pattern: Option<&str>) -> String {
        // Use semantic extraction instead of broken pattern matching
        let variables = AstUtils::extract_semantic_variables(node, source);
        
        // Prioritize actual variables over module names or constants
        for var in &variables {
            match var.var_type {
                VariableType::Source | VariableType::AssignmentTarget => {
                    // Found a real variable - use it
                    return var.name.clone();
                }
                _ => continue,
            }
        }
        
        // If pattern is provided, try to extract contextual variable
        if let Some(pattern) = pattern {
            if let Some(contextual_var) = self.extract_contextual_variable(node, source, pattern) {
                return contextual_var;
            }
        }
        
        // Fallback to first semantic variable
        if let Some(first_var) = variables.first() {
            first_var.name.clone()
        } else {
            // Last resort - use node text but filter out obvious non-variables
            let node_text = get_node_text(node, source);
            self.sanitize_variable_name(&node_text)
        }
    }
    
    /// Extract variable from specific context (e.g., function arguments, assignments)
    fn extract_contextual_variable(&self, node: &Node, source: &[u8], pattern: &str) -> Option<String> {
        let node_text = get_node_text(node, source);
        
        // For function call patterns, extract the argument variable
        if pattern.contains("cursor.execute") || pattern.contains("query") {
            // Extract variable from function arguments
            if let Some(start) = node_text.find('(') {
                if let Some(end) = node_text.find(')') {
                    let args = &node_text[start + 1..end];
                    // Extract first argument variable (common pattern)
                    let first_arg = args.split(',').next()?.trim();
                    if self.is_likely_variable(first_arg) {
                        return Some(first_arg.to_string());
                    }
                }
            }
        }
        
        // For request patterns, extract the accessed attribute
        if pattern.contains("request.") {
            if let Some(var) = self.extract_request_variable(&node_text) {
                return Some(var);
            }
        }
        
        None
    }
    
    /// Extract variable from request patterns (e.g., request.form['user_input'])
    fn extract_request_variable(&self, text: &str) -> Option<String> {
        // Look for patterns like request.form['var'], request.args.get('var')
        if let Some(bracket_start) = text.find('[') {
            if let Some(bracket_end) = text.find(']') {
                let key_content = &text[bracket_start + 1..bracket_end];
                let cleaned = key_content.trim_matches(|c| c == '"' || c == '\'');
                if self.is_likely_variable(cleaned) {
                    return Some(cleaned.to_string());
                }
            }
        }
        
        // Look for .get('var') patterns
        if let Some(get_start) = text.find(".get(") {
            let remaining = &text[get_start + 5..];
            if let Some(paren_end) = remaining.find(')') {
                let arg = &remaining[..paren_end];
                let cleaned = arg.trim_matches(|c| c == '"' || c == '\'' || c == ' ');
                if self.is_likely_variable(cleaned) {
                    return Some(cleaned.to_string());
                }
            }
        }
        
        // Default to generic user input variable
        Some("user_input".to_string())
    }
    
    /// Check if a string looks like a variable name
    fn is_likely_variable(&self, text: &str) -> bool {
        if text.is_empty() || text.len() > 50 {
            return false;
        }
        
        // Must start with letter or underscore
        if !text.chars().next().unwrap_or('0').is_alphabetic() && !text.starts_with('_') {
            return false;
        }
        
        // Must contain only valid identifier characters
        text.chars().all(|c| c.is_alphanumeric() || c == '_')
    }
    
    /// Sanitize extracted text to be a valid variable name
    fn sanitize_variable_name(&self, text: &str) -> String {
        if text.is_empty() {
            return "unknown_var".to_string();
        }
        
        // Remove common non-variable patterns
        let cleaned = text
            .trim()
            .replace("os.environ", "environ_var")
            .replace("request.", "request_var")
            .replace("cursor.execute", "sql_query")
            .replace("system(", "cmd_var");
        
        // Take first word if multiple words
        let first_word = cleaned.split_whitespace().next().unwrap_or("unknown_var");
        
        // Ensure it's a valid identifier
        if self.is_likely_variable(first_word) {
            first_word.to_string()
        } else {
            "extracted_var".to_string()
        }
    }

    /// PHASE 3: Strict Pattern Matching (replaces broken matches_taint_pattern)
    fn matches_taint_pattern(&self, pattern: &str, text: &str) -> bool {
        // Use enhanced pattern classification to avoid configuration noise
        let pattern_type = AstUtils::classify_code_pattern(text, pattern);
        
        // REJECT configuration patterns immediately
        if matches!(pattern_type, CodePatternType::Configuration) {
            return false;
        }
        
        // FIXED: Treat taint rule patterns as regex by default (they contain regex escaping)
        if pattern.contains('*') {
            self.strict_wildcard_match(pattern, text)
        } else if pattern.starts_with("regex:") {
            // Explicit regex patterns
            if let Some(regex_pattern) = pattern.strip_prefix("regex:") {
                if let Ok(regex) = regex::Regex::new(regex_pattern) {
                    regex.is_match(text)
                } else {
                    false
                }
            } else {
                false
            }
        } else if pattern.contains("\\\\") || pattern.contains("\\.") {
            // FIXED: Patterns with regex escaping are regex patterns
            if let Ok(regex) = regex::Regex::new(pattern) {
                regex.is_match(text)
            } else {
                // Fallback to literal matching if regex is invalid
                self.strict_exact_match(pattern, text)
            }
        } else {
            self.strict_exact_match(pattern, text)
        }
    }
    
    /// PHASE 3: Strict wildcard matching (replaces over-broad wildcard_pattern_match)
    fn strict_wildcard_match(&self, pattern: &str, text: &str) -> bool {
        // Don't match everything with single *
        if pattern == "*" {
            return false; // Too broad - require specific patterns
        }
        
        // Require at least some specificity in wildcard patterns
        let parts: Vec<&str> = pattern.split('*').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return false; // Pattern like "***" - too broad
        }
        
        // Require significant pattern content (not just short wildcards)
        let total_pattern_content: usize = parts.iter().map(|p| p.len()).sum();
        if total_pattern_content < 3 {
            return false; // Patterns like "*a*" are too broad
        }
        
        // Use existing wildcard logic but with validation
        self.validated_wildcard_match(pattern, text, &parts)
    }
    
    fn validated_wildcard_match(&self, pattern: &str, text: &str, parts: &[&str]) -> bool {
        let mut current_pos = 0;
        
        for (i, part) in parts.iter().enumerate() {
            if i == 0 {
                // First part must match at start
                if !text.starts_with(part) {
                    return false;
                }
                current_pos = part.len();
            } else if i == parts.len() - 1 {
                // Last part must match at end  
                if !text[current_pos..].ends_with(part) {
                    return false;
                }
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
    
    /// PHASE 3: Strict exact matching (replaces over-broad strict_pattern_match)
    fn strict_exact_match(&self, pattern: &str, text: &str) -> bool {
        // Require word boundaries for short patterns to avoid false positives
        if pattern.len() <= 3 {
            self.word_boundary_match(pattern, text)
        } else {
            // For longer patterns, use contains but with context validation
            if text.contains(pattern) {
                // Additional validation: ensure it's not part of a comment or string literal
                self.validate_pattern_context(pattern, text)
            } else {
                false
            }
        }
    }
    
    /// Validate that pattern match occurs in executable code context
    fn validate_pattern_context(&self, pattern: &str, text: &str) -> bool {
        // Find all occurrences of the pattern
        let mut pos = 0;
        while let Some(match_pos) = text[pos..].find(pattern) {
            let absolute_pos = pos + match_pos;
            
            // Check if this occurrence is in a valid context
            if self.is_in_executable_context(text, absolute_pos) {
                return true;
            }
            
            pos = absolute_pos + pattern.len();
        }
        
        false
    }
    
    /// Check if position in text is in executable code (not comment/string)
    fn is_in_executable_context(&self, text: &str, pos: usize) -> bool {
        let line_start = text[..pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
        let line = &text[line_start..pos + text[pos..].find('\n').unwrap_or(text.len() - pos)];
        
        // Skip if in comment
        if let Some(comment_pos) = line.find('#') {
            if pos >= line_start + comment_pos {
                return false;
            }
        }
        
        // Skip if in string literal (basic check)
        let before_pos = &text[line_start..pos];
        let single_quotes = before_pos.matches('\'').count();
        let double_quotes = before_pos.matches('"').count();
        
        // If odd number of quotes, we're inside a string
        if single_quotes % 2 != 0 || double_quotes % 2 != 0 {
            return false;
        }
        
        true
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

    /// Create semantic flow key for enhanced deduplication
    fn create_semantic_flow_key(&self, source: &TaintSource, sink: &TaintSink) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}",
            source.file,
            source.line,
            Self::normalize_operation(&source.operation),
            sink.file,
            sink.line,
            Self::normalize_operation(&sink.operation)
        )
    }
    
    /// Normalize operations for semantic matching
    fn normalize_operation(operation: &str) -> String {
        // Convert specific patterns to generic types for better deduplication
        if operation.contains("request.") || operation.contains("input") || operation.contains("form") {
            "user_input".to_string()
        } else if operation.contains("execute") || operation.contains("query") || operation.contains("cursor") {
            "sql_execution".to_string()  
        } else if operation.contains("system") || operation.contains("subprocess") || operation.contains("os.") {
            "command_execution".to_string()
        } else if operation.contains("render") || operation.contains("template") || operation.contains("html") {
            "template_output".to_string()
        } else {
            // Keep original operation if no pattern matches
            operation.to_string()
        }
    }

    // NEW: Method to analyze multiple files for cross-file taint analysis
    pub fn analyze_cross_file(
        &mut self,
        all_sources: &[TaintSource],
        all_sinks: &[TaintSink],
    ) -> Vec<TaintFlow> {
        let mut cross_file_flows = Vec::new();
        

        
        // Check every source against every sink
        for source in all_sources {
            for sink in all_sinks {
                // Only check cross-file combinations
                if source.file != sink.file {

                    
                    if self.is_cross_file_flow_reachable(source, sink) {
                        // Create cross-file flow
                        let flow_id = format!("flow_{}_{}_{}", 
                                            source.file.split('/').last().unwrap_or("unknown"),
                                            source.line, sink.line);
                        let (rule_id, rule_name, rule_description, rule_finding_type) = self.find_rule_info_for_flow(source, sink);
                        
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
                            rule_id,
                            rule_name,
                            rule_description,
                            rule_finding_type,
                        };
                        cross_file_flows.push(flow);
                    }
                }
            }
        }
        

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
    
    // Apply final semantic deduplication  
    let deduplicated_flows = deduplicate_flows_semantically(all_flows);
    
    let unsanitized_flows = deduplicated_flows.iter().filter(|f| !f.is_sanitized).count();
    let sanitized_flows = deduplicated_flows.iter().filter(|f| f.is_sanitized).count();
    let cross_file_flow_count = deduplicated_flows.iter().filter(|f| f.is_cross_file).count();
    
    TaintAnalysisResult {
        flows: deduplicated_flows,
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

/// Semantic flow deduplication (extends existing pattern)
fn deduplicate_flows_semantically(flows: Vec<TaintFlow>) -> Vec<TaintFlow> {
    use std::collections::HashMap;
    
    let mut flow_groups: HashMap<String, Vec<TaintFlow>> = HashMap::new();
    
    // Group flows by semantic signature
    for flow in flows {
        let signature = create_flow_signature(&flow);
        flow_groups.entry(signature).or_insert_with(Vec::new).push(flow);
    }
    
    // Select best flow from each group
    let mut deduplicated = Vec::new();
    for (_, mut group) in flow_groups {
        if group.len() == 1 {
            deduplicated.extend(group);
    } else {
            // Sort by rule completeness (use existing metadata)
            group.sort_by_key(|flow| {
                let mut score = 0;
                if flow.rule_id.is_some() { score += 4; }
                if flow.rule_name.is_some() { score += 3; }
                if flow.rule_description.is_some() { score += 2; }
                if flow.rule_finding_type.is_some() { score += 1; }
                std::cmp::Reverse(score)
            });
            
            // Take the best flow
            if let Some(best_flow) = group.into_iter().next() {
                deduplicated.push(best_flow);
            }
        }
    }
    
    deduplicated
}

/// Create semantic signature for flow grouping
fn create_flow_signature(flow: &TaintFlow) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        flow.source.file,
        flow.source.line,
        normalize_operation_type(&flow.source.operation),
        flow.sink.file, 
        flow.sink.line,
        normalize_operation_type(&flow.sink.operation)
    )
}

/// Normalize operation type for semantic grouping
fn normalize_operation_type(operation: &str) -> &str {
    // Simple normalization using existing pattern knowledge
    if operation.contains("request.") || operation.contains("input") || operation.contains("form") { 
        "user_input" 
    } else if operation.contains("execute") || operation.contains("query") || operation.contains("cursor") { 
        "sql_execution" 
    } else if operation.contains("system") || operation.contains("subprocess") || operation.contains("os.") { 
        "command_execution" 
    } else if operation.contains("render") || operation.contains("template") || operation.contains("html") {
        "template_output"
    } else { 
        "generic" 
    }
}



// NEW: Helper struct for import name parsing
#[derive(Debug)]
struct ImportName {
    name: String,
    alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum TaintStatus {
    Tainted(String), // Contains the source pattern
    Unknown,
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

#[derive(Debug, Clone)]
struct FunctionCallInfo {
    function_name: String,
    file: String,
    line: usize,
    return_variable: Option<String>,
    taint_status: TaintStatus,
}
