use std::collections::{HashMap, HashSet, VecDeque};
use tree_sitter::{Node, Tree};
use crate::scanner::utils::{AstUtils, VariableType};

/// Data flow graph for tracking variable assignments and usage
#[derive(Debug, Clone)]
pub struct DataFlowGraph {
    /// Maps variable names to their assignments
    assignments: HashMap<String, Vec<Assignment>>,
    /// Maps variable names to their usages
    usages: HashMap<String, Vec<Usage>>,
    /// Function-level scope tracking
    scopes: HashMap<String, Scope>,
    /// NEW: Control flow branch tracking for variable isolation
    control_flow_branches: HashMap<String, ControlFlowBranch>,
    /// NEW: Maps variables to their containing branch for isolation
    branch_variable_isolation: HashMap<String, HashSet<String>>,
}

/// NEW: Control flow branch tracking for data flow analysis
#[derive(Debug, Clone)]
pub struct ControlFlowBranch {
    pub branch_id: String,
    pub branch_type: ControlFlowBranchType,
    pub line_start: usize,
    pub line_end: usize,
    pub variables: HashSet<String>,
    pub mutually_exclusive_branches: Vec<String>,
    pub parent_branch: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ControlFlowBranchType {
    If,
    Elif,
    Else,
    Function,
    Global,
}

#[derive(Debug, Clone)]
pub struct Assignment {
    pub variable: String,
    pub source_variables: Vec<String>,
    pub line: usize,
    pub assignment_type: AssignmentType,
    pub context: String,
    /// NEW: Branch where this assignment occurs
    pub branch_id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum AssignmentType {
    Direct,           // x = y
    FunctionCall,     // x = func(y)
    Expression,       // x = y + z
    UserInput,        // x = input()
}

#[derive(Debug, Clone)]
pub struct Usage {
    pub variable: String,
    pub line: usize,
    pub usage_type: UsageType,
    pub context: String,
    /// NEW: Branch where this usage occurs
    pub branch_id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum UsageType {
    FunctionArgument,
    Assignment,
    Return,
}

#[derive(Debug, Clone)]
pub struct Scope {
    pub function_name: String,
    pub variables: HashSet<String>,
    pub parameters: Vec<String>,
}

impl DataFlowGraph {
    pub fn new() -> Self {
        Self {
            assignments: HashMap::new(),
            usages: HashMap::new(),
            scopes: HashMap::new(),
            control_flow_branches: HashMap::new(),
            branch_variable_isolation: HashMap::new(),
        }
    }
    
    /// Build data flow graph from AST with control flow awareness
    pub fn build_from_ast(&mut self, tree: &Tree, source: &[u8], _filepath: &str) {
        self.traverse_and_build(tree.root_node(), source, "global", None);
    }
    
    /// NEW: Enhanced traverse with branch tracking
    fn traverse_and_build(&mut self, node: Node, source: &[u8], current_function: &str, current_branch: Option<&str>) {
        let _node_text = crate::parser::get_node_text(&node, source);
        let line = node.start_position().row + 1;
        
        match node.kind() {
            "function_definition" => {
                let func_name = self.extract_function_name(&node, source);
                let parameters = self.extract_function_parameters(&node, source);
                
                // Create function-level branch
                let func_branch_id = format!("func_{}_{}", func_name, line);
                self.add_branch(func_branch_id.clone(), ControlFlowBranchType::Function, line, line);
                
                self.scopes.insert(func_name.clone(), Scope {
                    function_name: func_name.clone(),
                    variables: HashSet::new(),
                    parameters,
                });
                
                // Recursively process function body with function branch
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        self.traverse_and_build(cursor.node(), source, &func_name, Some(&func_branch_id));
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                return;
            }
            "if_statement" => {
                let branch_id = format!("if_{}_{}", line, current_function);
                self.add_branch(branch_id.clone(), ControlFlowBranchType::If, line, line);
                
                // Process if block with new branch context
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        self.traverse_and_build(cursor.node(), source, current_function, Some(&branch_id));
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                return;
            }
            "elif_clause" => {
                let branch_id = format!("elif_{}_{}", line, current_function);
                self.add_branch(branch_id.clone(), ControlFlowBranchType::Elif, line, line);
                
                // Add mutual exclusion with previous if/elif branches
                self.add_mutual_exclusion_for_elif(&branch_id, current_function, line);
                
                // Process elif block
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        self.traverse_and_build(cursor.node(), source, current_function, Some(&branch_id));
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                return;
            }
            "else_clause" => {
                let branch_id = format!("else_{}_{}", line, current_function);
                self.add_branch(branch_id.clone(), ControlFlowBranchType::Else, line, line);
                
                // Add mutual exclusion with all if/elif branches
                self.add_mutual_exclusion_for_else(&branch_id, current_function, line);
                
                // Process else block
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        self.traverse_and_build(cursor.node(), source, current_function, Some(&branch_id));
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                return;
            }
            "assignment" | "assignment_expression" => {
                self.process_assignment(&node, source, line, current_function, current_branch);
            }
            "call" => {
                self.process_function_call(&node, source, line, current_function, current_branch);
            }
            _ => {}
        }
        
        // Recursively process children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.traverse_and_build(cursor.node(), source, current_function, current_branch);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    
    /// NEW: Add control flow branch
    fn add_branch(&mut self, branch_id: String, branch_type: ControlFlowBranchType, line_start: usize, line_end: usize) {
        let branch = ControlFlowBranch {
            branch_id: branch_id.clone(),
            branch_type,
            line_start,
            line_end,
            variables: HashSet::new(),
            mutually_exclusive_branches: Vec::new(),
            parent_branch: None,
        };
        
        self.control_flow_branches.insert(branch_id, branch);
    }
    
    /// NEW: Add mutual exclusion for elif branches
    fn add_mutual_exclusion_for_elif(&mut self, elif_branch_id: &str, function: &str, line: usize) {
        // Find all if/elif branches in the same function before this line
        let mut exclusive_branches = Vec::new();
        
        for (branch_id, branch) in &self.control_flow_branches {
            if branch.line_start < line && 
               branch_id.contains(function) &&
               (matches!(branch.branch_type, ControlFlowBranchType::If) || 
                matches!(branch.branch_type, ControlFlowBranchType::Elif)) {
                exclusive_branches.push(branch_id.clone());
            }
        }
        
        // Add mutual exclusion
        if let Some(elif_branch) = self.control_flow_branches.get_mut(elif_branch_id) {
            elif_branch.mutually_exclusive_branches.extend(exclusive_branches.clone());
        }
        
        // Add reverse mutual exclusion
        for branch_id in exclusive_branches {
            if let Some(branch) = self.control_flow_branches.get_mut(&branch_id) {
                branch.mutually_exclusive_branches.push(elif_branch_id.to_string());
            }
        }
    }
    
    /// NEW: Add mutual exclusion for else branches
    fn add_mutual_exclusion_for_else(&mut self, else_branch_id: &str, function: &str, line: usize) {
        // Find all if/elif branches in the same function before this line
        let mut exclusive_branches = Vec::new();
        
        for (branch_id, branch) in &self.control_flow_branches {
            if branch.line_start < line && 
               branch_id.contains(function) &&
               (matches!(branch.branch_type, ControlFlowBranchType::If) || 
                matches!(branch.branch_type, ControlFlowBranchType::Elif)) {
                exclusive_branches.push(branch_id.clone());
            }
        }
        
        // Add mutual exclusion
        if let Some(else_branch) = self.control_flow_branches.get_mut(else_branch_id) {
            else_branch.mutually_exclusive_branches.extend(exclusive_branches.clone());
        }
        
        // Add reverse mutual exclusion
        for branch_id in exclusive_branches {
            if let Some(branch) = self.control_flow_branches.get_mut(&branch_id) {
                branch.mutually_exclusive_branches.push(else_branch_id.to_string());
            }
        }
    }
    
    /// Enhanced process assignment with branch tracking
    fn process_assignment(&mut self, node: &Node, source: &[u8], line: usize, _function: &str, current_branch: Option<&str>) {
        let variables = AstUtils::extract_semantic_variables(node, source);
        let node_text = crate::parser::get_node_text(node, source);
        
        // Find assignment target
        if let Some(target) = variables.iter()
            .find(|v| matches!(v.var_type, VariableType::AssignmentTarget)) {
            
            // Find source variables
            let source_vars: Vec<String> = variables.iter()
                .filter(|v| matches!(v.var_type, VariableType::Source))
                .map(|v| v.name.clone())
                .collect();
            
            let assignment_type = if node_text.contains("input(") || node_text.contains("request.") {
                AssignmentType::UserInput
            } else if node_text.contains('(') && node_text.contains(')') {
                AssignmentType::FunctionCall
            } else if source_vars.len() > 1 {
                AssignmentType::Expression
            } else {
                AssignmentType::Direct
            };
            
            let assignment = Assignment {
                variable: target.name.clone(),
                source_variables: source_vars,
                line,
                assignment_type,
                context: node_text,
                branch_id: current_branch.map(|s| s.to_string()),
            };
            
            self.assignments.entry(target.name.clone())
                .or_insert_with(Vec::new)
                .push(assignment);
            
            // Track variable in branch
            if let Some(branch_id) = current_branch {
                self.add_variable_to_branch(branch_id, target.name.clone());
            }
        }
    }
    
    /// Enhanced process function call with branch tracking
    fn process_function_call(&mut self, node: &Node, source: &[u8], line: usize, _function: &str, current_branch: Option<&str>) {
        let variables = AstUtils::extract_semantic_variables(node, source);
        let node_text = crate::parser::get_node_text(node, source);
        
        // Track variable usage in function arguments
        for var in variables.iter()
            .filter(|v| matches!(v.var_type, VariableType::FunctionArgument)) {
            
            let usage = Usage {
                variable: var.name.clone(),
                line,
                usage_type: UsageType::FunctionArgument,
                context: node_text.clone(),
                branch_id: current_branch.map(|s| s.to_string()),
            };
            
            self.usages.entry(var.name.clone())
                .or_insert_with(Vec::new)
                .push(usage);
                
            // Track variable in branch
            if let Some(branch_id) = current_branch {
                self.add_variable_to_branch(branch_id, var.name.clone());
            }
        }
    }
    
    /// NEW: Add variable to branch tracking
    fn add_variable_to_branch(&mut self, branch_id: &str, variable: String) {
        if let Some(branch) = self.control_flow_branches.get_mut(branch_id) {
            branch.variables.insert(variable.clone());
        }
        
        self.branch_variable_isolation
            .entry(variable)
            .or_insert_with(HashSet::new)
            .insert(branch_id.to_string());
    }
    
    /// NEW: Enhanced find flow path with branch-aware validation
    pub fn find_flow_path_with_scope(
        &self, 
        source_var: &str, 
        sink_var: &str, 
        source_branch: Option<&str>,
        sink_branch: Option<&str>,
        source_line: usize, 
        sink_line: usize
    ) -> Option<FlowPath> {
        // Check branch compatibility first
        if let (Some(src_branch), Some(sink_branch)) = (source_branch, sink_branch) {
            if self.are_branches_mutually_exclusive(src_branch, sink_branch) {
                return None; // Cannot flow between mutually exclusive branches
            }
        }
        
        // Use existing flow path finding logic
        self.find_flow_path(source_var, sink_var, source_line, sink_line)
    }
    
    /// NEW: Check if branches are mutually exclusive
    pub fn are_branches_mutually_exclusive(&self, branch_id1: &str, branch_id2: &str) -> bool {
        if let Some(branch1) = self.control_flow_branches.get(branch_id1) {
            return branch1.mutually_exclusive_branches.contains(&branch_id2.to_string());
        }
        false
    }

    /// Find data flow path between two variables
    pub fn find_flow_path(&self, source_var: &str, sink_var: &str, source_line: usize, sink_line: usize) -> Option<FlowPath> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let path = Vec::new();
        
        // Start BFS from source variable
        queue.push_back((source_var.to_string(), source_line, path.clone()));
        
        while let Some((current_var, current_line, current_path)) = queue.pop_front() {
            if visited.contains(&current_var) {
                continue;
            }
            visited.insert(current_var.clone());
            
            // Check if we reached the sink
            if current_var == sink_var && current_line <= sink_line {
                return Some(FlowPath {
                    steps: current_path,
                    is_valid: true,
                });
            }
            
            // Find assignments that use this variable
            if let Some(assignments) = self.assignments.get(&current_var) {
                for assignment in assignments {
                    if assignment.line > current_line && assignment.line < sink_line {
                        let mut new_path = current_path.clone();
                        new_path.push(FlowStep {
                            variable: assignment.variable.clone(),
                            line: assignment.line,
                            step_type: FlowStepType::Assignment,
                            context: assignment.context.clone(),
                        });
                        queue.push_back((assignment.variable.clone(), assignment.line, new_path));
                    }
                }
            }
            
            // Find variables assigned from this variable
            for (var_name, assignments) in &self.assignments {
                for assignment in assignments {
                    if assignment.source_variables.contains(&current_var) && 
                       assignment.line > current_line && assignment.line < sink_line {
                        let mut new_path = current_path.clone();
                        new_path.push(FlowStep {
                            variable: var_name.clone(),
                            line: assignment.line,
                            step_type: FlowStepType::Propagation,
                            context: assignment.context.clone(),
                        });
                        queue.push_back((var_name.clone(), assignment.line, new_path));
                    }
                }
            }
        }
        
        None
    }
    
    /// Check if a variable is tainted (user input)
    pub fn is_variable_tainted(&self, variable: &str) -> bool {
        if let Some(assignments) = self.assignments.get(variable) {
            return assignments.iter().any(|a| matches!(a.assignment_type, AssignmentType::UserInput));
        }
        false
    }
    
    // Helper methods
    fn extract_function_name(&self, node: &Node, source: &[u8]) -> String {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if cursor.node().kind() == "identifier" {
                    return crate::parser::get_node_text(&cursor.node(), source);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        "unknown_function".to_string()
    }
    
    fn extract_function_parameters(&self, _node: &Node, _source: &[u8]) -> Vec<String> {
        // Implementation for extracting function parameters
        Vec::new() // Simplified for now
    }
}

#[derive(Debug, Clone)]
pub struct FlowPath {
    pub steps: Vec<FlowStep>,
    pub is_valid: bool,
}

#[derive(Debug, Clone)]
pub struct FlowStep {
    pub variable: String,
    pub line: usize,
    pub step_type: FlowStepType,
    pub context: String,
}

#[derive(Debug, Clone)]
pub enum FlowStepType {
    Assignment,
    Propagation,
    FunctionCall,
} 