use serde::{Deserialize, Serialize};

// Keep these constants as they might be useful
pub const DEFAULT_SEVERITY: &str = "High";
pub const DEFAULT_CONFIDENCE: &str = "Medium";

// Keep basic data structures that are part of the public API
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

// Simple result structure for backwards compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisResult {
    pub flows: Vec<crate::models::TaintFlow>,
    pub summary: crate::models::TaintSummary,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub cross_file_flows: Vec<CrossFileFlow>,
    pub sources: Vec<crate::models::TaintSource>,
    pub sinks: Vec<crate::models::TaintSink>,
}

impl TaintAnalysisResult {
    /// Convert taint analysis results to unified Finding format
    pub fn to_findings(&self) -> Vec<crate::models::Finding> {
        use crate::models::*;
        
        self.flows.iter().map(|flow| Finding {
            file: flow.sink.file.clone(),
            line: flow.sink.line,
            column: 0,
            end_line: flow.sink.line,
            end_column: 0,
            function: flow.sink.function.clone(),
            finding_type: flow.rule_finding_type.clone()
                .unwrap_or_else(|| format!("taint_flow_{}", flow.flow_id)),
            snippet: flow.sink.code.clone(),
            severity: flow.severity.clone(),
            confidence: flow.confidence.clone(),
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

// Simple merge function for backwards compatibility
pub fn merge_taint_results(results: Vec<TaintAnalysisResult>) -> TaintAnalysisResult {
    if results.is_empty() {
        return TaintAnalysisResult {
            flows: Vec::new(),
            summary: crate::models::TaintSummary {
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
    
    let files_analyzed = results.len(); // Calculate length before moving
    let mut all_flows = Vec::new();
    let mut all_imports = Vec::new();
    let mut all_exports = Vec::new();
    let mut all_cross_file_flows = Vec::new();
    let mut all_sources = Vec::new();
    let mut all_sinks = Vec::new();
    
    for result in results {
        all_flows.extend(result.flows);
        all_imports.extend(result.imports);
        all_exports.extend(result.exports);
        all_cross_file_flows.extend(result.cross_file_flows);
        all_sources.extend(result.sources);
        all_sinks.extend(result.sinks);
    }
    
    let total_flows = all_flows.len();
    let unsanitized_flows = all_flows.iter().filter(|f| !f.is_sanitized).count();
    let sanitized_flows = total_flows - unsanitized_flows;
    let cross_file_flows = all_flows.iter().filter(|f| f.is_cross_file).count();
    
    TaintAnalysisResult {
        flows: all_flows,
        summary: crate::models::TaintSummary {
            total_flows,
            unsanitized_flows,
            sanitized_flows,
            cross_file_flows,
            files_analyzed,
            functions_analyzed: 0, // Simplified
        },
        imports: all_imports,
        exports: all_exports,
        cross_file_flows: all_cross_file_flows,
        sources: all_sources,
        sinks: all_sinks,
    }
}

// Stub structures for backwards compatibility (no longer used)
pub struct TaintAnalyzer;

impl TaintAnalyzer {
    pub fn new(_rules: crate::rules::Rules) -> Self {
        TaintAnalyzer
    }
    
    #[deprecated(note = "Use the unified scanner in VulnerabilityScanner::find_vulnerabilities_unified instead")]
    pub fn analyze_file(
        &mut self,
        _filepath: &str,
        _source: &[u8],
        _tree: &tree_sitter::Tree,
        _language_support: &dyn crate::language::LanguageSupport,
    ) -> TaintAnalysisResult {
        // Return empty result - this method is deprecated
        TaintAnalysisResult {
            flows: Vec::new(),
            summary: crate::models::TaintSummary {
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
        }
    }
    
    #[deprecated(note = "Cross-file analysis is now handled by the unified scanner")]
    pub fn analyze_cross_file(
        &mut self,
        _all_sources: &[crate::models::TaintSource],
        _all_sinks: &[crate::models::TaintSink],
    ) -> Vec<crate::models::TaintFlow> {
        Vec::new()
    }
}
