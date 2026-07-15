#![allow(clippy::too_many_arguments, clippy::large_enum_variant, clippy::needless_range_loop)]

#[derive(Debug)]
pub(crate) struct VariableFlowTracker {
    /// Maps variable names to their taint source information
    tainted_variables: std::collections::BTreeMap<String, TaintVariableInfo>,
}

#[derive(Debug, Clone)]
pub(crate) struct TaintVariableInfo {
    pub(crate) source_line: usize,
    pub(crate) source_pattern: String,
    pub(crate) source_function: String,
    pub(crate) assignment_code: String,
}

impl VariableFlowTracker {
    pub(crate) fn new() -> Self {
        Self { tainted_variables: std::collections::BTreeMap::new() }
    }

    /// Record a variable as tainted from a source
    pub(crate) fn record_tainted_variable(
        &mut self,
        var_name: String,
        source_info: TaintVariableInfo,
    ) {
        log::debug!("[RECORD_TAINT] Recording tainted variable: '{}' from pattern '{}' at line {} in function '{}'", 
            var_name, source_info.source_pattern, source_info.source_line, source_info.source_function);

        self.tainted_variables.insert(var_name.clone(), source_info.clone());
    }

    /// Check if a variable is tainted
    pub(crate) fn is_variable_tainted(
        &self,
        var_name: &str,
        function: &str,
    ) -> Option<&TaintVariableInfo> {
        log::debug!(
            "[CHECK_TAINT] Checking if variable '{}' is tainted in function '{}'",
            var_name,
            function
        );

        // Check direct variable
        if let Some(info) = self.tainted_variables.get(var_name) {
            log::debug!(
                "[CHECK_TAINT] Found taint info: source_function='{}', source_pattern='{}'",
                info.source_function,
                info.source_pattern
            );

            // Same function or global variable
            if info.source_function == function || Self::is_global_variable(var_name) {
                log::debug!(
                    "[CHECK_TAINT] Variable '{}' is tainted (function match or global)",
                    var_name
                );
                return Some(info);
            } else {
                log::debug!("[CHECK_TAINT] Variable '{}' found but function mismatch: source='{}' vs current='{}'", 
                    var_name, info.source_function, function);
            }
        } else {
            log::debug!("[CHECK_TAINT] Variable '{}' not found in tainted variables", var_name);
        }
        None
    }

    /// Check if variable is likely global/passed between functions (reusing existing logic)
    fn is_global_variable(var_name: &str) -> bool {
        // Simple heuristics for global variables
        var_name.to_uppercase() == var_name || // ALL_CAPS
        var_name.starts_with("app.") ||        // app.something
        var_name.contains("_DIR") ||           // paths
        var_name.contains("_PATH") // paths
    }
}

// ============================================================================
// ENHANCED DATA STRUCTURES - Phase 1: Precise Cross-File Analysis
// ============================================================================

/// Source/sink endpoints for [`MultiFileTaintAnalyzer::create_verified_flow`], bundled to keep
/// that function's signature under the 8-parameter gate.
pub(crate) struct VerifiedFlowEndpoints<'a> {
    pub(crate) source_file: &'a str,
    pub(crate) source_function: &'a str,
    pub(crate) source_pattern: &'a str,
    pub(crate) source_line: usize,
    pub(crate) sink_file: &'a str,
    pub(crate) sink_function: &'a str,
    pub(crate) sink_pattern: &'a str,
    pub(crate) sink_line: usize,
    pub(crate) sink_variable: &'a str,
    pub(crate) call_chain_len: usize,
}

/// A verified taint flow with complete evidence chain
#[derive(Debug, Clone)]
pub(crate) struct VerifiedTaintFlow {
    pub(crate) source_file: String,
    pub(crate) source_function: String,
    pub(crate) source_pattern: String,
    pub(crate) source_line: usize,

    pub(crate) sink_file: String,
    pub(crate) sink_function: String,
    pub(crate) sink_pattern: String,
    pub(crate) sink_line: usize,
    pub(crate) sink_variable: String,

    /// Number of cross-file calls traversed to reach the sink (used for reporting).
    pub(crate) call_chain_len: usize,
}

/// Invariant context for
/// [`MultiFileTaintAnalyzer::analyze_function_taint_behavior`]'s per-line helpers: the
/// file/function whose body is being analyzed.
pub(crate) struct FunctionAnalysisSite<'a> {
    pub(crate) file_path: &'a str,
    pub(crate) function_name: &'a str,
}

/// Accumulated taint state (tainted locals so far, and any "ambient" taint source) passed to
/// [`MultiFileTaintAnalyzer::check_return_statement_taint`], bundled to keep that function's
/// parameter count small.
pub(crate) struct FunctionTaintScanState<'a> {
    pub(crate) tainted_locals: &'a std::collections::BTreeMap<String, VerifiedTaintFlow>,
    pub(crate) ambient_taint: &'a Option<VerifiedTaintFlow>,
}

/// Sink-side identity shared across [`MultiFileTaintAnalyzer::trace_local_assignment_taint`]'s
/// helpers: the file/function being traced and the sink being fed.
pub(crate) struct TraceSinkSite<'a> {
    pub(crate) file_path: &'a str,
    pub(crate) function_name: &'a str,
    pub(crate) sink_pattern: &'a str,
    pub(crate) sink_line: usize,
    pub(crate) sink_variable: &'a str,
}

/// Classification of how a variable gets its value
#[derive(Debug, Clone)]
pub(crate) enum VariableSource {
    LocalAssignment { source_expression: String, line: usize },
    KnownSafe { reason: String, line: usize },
    FunctionParameter { parameter_index: usize },
    DirectTaintSource { pattern: String, line: usize },
}

/// Analysis result enumeration for conservative approach
#[derive(Debug, Clone)]
pub(crate) enum AnalysisResult {
    DefinitelyTainted { flow: VerifiedTaintFlow },
    DefinitelySafe,
    Unknown { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueSourceClassification {
    Safe(String),
    Tainted(String),
    Unknown,
}

/// Identity of a verified cross-file taint flow, used to dedup rediscovered flows:
/// `(sink_file, sink_line, sink_variable, sink_pattern, source_file, source_line,
/// source_pattern)`.
pub(crate) type CrossFileFlowKey = (String, usize, String, String, String, usize, String);
