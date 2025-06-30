use serde::Serialize;

// Re-export the types for backward compatibility
pub use crate::models::{Finding, SourceInfo, SinkInfo, TraceStep, TaintFlow, TaintSource, TaintSink, TaintTrace, TaintSummary, FileInfo, TraceType};

// Separate structure for taint analysis results
#[derive(Debug, Clone, Serialize)]
pub struct TaintAnalysisResult {
    pub flows: Vec<TaintFlow>,
    pub isolated_sources: Vec<TaintSource>,
    pub isolated_sinks: Vec<TaintSink>,
    pub summary: TaintSummary,
} 