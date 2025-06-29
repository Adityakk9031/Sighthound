use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub function: String,
    pub finding_type: String,
    pub snippet: String,
    pub severity: String,
    pub confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_info: Option<SourceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_info: Option<SinkInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traces: Option<Vec<TraceStep>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceInfo {
    pub source_type: String,
    pub location: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SinkInfo {
    pub sink_type: String,
    pub function_name: String,
    pub location: String,
    pub variable: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceStep {
    pub file: String,
    pub line: usize,
    pub code: String,
    pub variable: String,
    pub operation: String,   // "assignment", "parameter", "return", "method_call"
    pub function: String,    // Containing function name
}

// Separate structure for taint analysis results
#[derive(Debug, Clone, Serialize)]
pub struct TaintAnalysisResult {
    pub flows: Vec<TaintFlow>,
    pub isolated_sources: Vec<TaintSource>,
    pub isolated_sinks: Vec<TaintSink>,
    pub summary: TaintSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaintFlow {
    pub flow_id: String,
    pub flow_type: String, // "sql_injection", "command_injection", etc.
    pub severity: String,
    pub confidence: String,
    pub file: String,
    pub source: TaintSource,
    pub sink: TaintSink,
    pub traces: Vec<TaintTrace>,
    pub is_sanitized: bool,
    pub sanitizer: Option<TaintSanitizer>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaintSource {
    pub line: usize,
    pub code: String,
    pub variable: String,
    pub source_type: String, // "user_input", "file", "database", etc.
    pub function: String,    // Containing function name
}

#[derive(Debug, Clone, Serialize)]
pub struct TaintSink {
    pub line: usize,
    pub code: String,
    pub variable: String,
    pub sink_type: String,   // "sql_execution", "command_execution", etc.
    pub function: String,    // Containing function name
}

#[derive(Debug, Clone, Serialize)]
pub struct TaintTrace {
    pub line: usize,
    pub code: String,
    pub from_variable: String,
    pub to_variable: String,
    pub operation: String,   // "assignment", "concatenation", "method_call"
    pub function: String,    // Containing function name
}

#[derive(Debug, Clone, Serialize)]
pub struct TaintSanitizer {
    pub line: usize,
    pub code: String,
    pub sanitizer_type: String,
    pub function: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaintSummary {
    pub total_flows: usize,
    pub critical_flows: usize,
    pub sanitized_flows: usize,
    pub isolated_sources: usize,
    pub isolated_sinks: usize,
    pub flow_types: std::collections::HashMap<String, usize>,
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
    pub extension: Option<String>,
}

