//! AST-grounded variable provenance for Python.
//!
//! Resolves "where does this variable get its value?" from the tree-sitter AST
//! instead of scanning source lines as text. This makes provenance robust to
//! shapes the text scan cannot see (multiline, annotated, augmented, chained,
//! and tuple assignments; `for` targets) and immune to shapes the text scan
//! wrongly matches (assignment-like text inside docstrings, same-named
//! variables in other functions).
//!
//! The resolver reports structural facts only — classification of an RHS as
//! safe or tainted stays in [`crate::scanner::dataflow`]. Any construct it
//! does not model yields `None`, and callers fall back to the existing text
//! path, so unsupported shapes keep today's behavior.

use crate::parser::{get_node_text_slice, LanguageParser};
use tree_sitter::Node;

/// How a variable received a value, in source order within one function.
#[derive(Debug, Clone)]
pub(crate) struct AssignmentFact {
    /// Simple identifier target this fact is recorded for.
    pub(crate) target: String,
    /// Whitespace-normalized text of the assigned value expression.
    pub(crate) rhs: String,
    /// 1-based file line of the assignment statement.
    pub(crate) line: usize,
    /// `x += ...`: the value depends on the prior value of `x` as well.
    pub(crate) augmented: bool,
    /// The RHS is a collection literal containing only literals, so every
    /// value the target can take is developer-controlled.
    pub(crate) literal_collection: bool,
}

/// Outcome of resolving one variable within one function.
#[derive(Debug)]
pub(crate) enum AstResolution {
    /// All assignments to the variable in the function body, in source order.
    Assignments(Vec<AssignmentFact>),
    /// The variable is the function's parameter at `index`.
    Parameter { index: usize },
}

#[derive(Debug, Clone)]
struct FunctionFacts {
    parameters: Vec<String>,
    assignments: Vec<AssignmentFact>,
}

#[derive(Debug)]
struct FileFacts {
    /// First definition in document order wins, matching the text path.
    functions: std::collections::BTreeMap<String, FunctionFacts>,
}

/// Per-file cache of extracted Python function facts. `None` entries record
/// files that could not be read or parsed so they are not retried.
#[derive(Debug, Default)]
pub(crate) struct PythonAstProvenance {
    file_cache: std::collections::HashMap<String, Option<FileFacts>>,
}

impl PythonAstProvenance {
    /// Resolve `variable_name` within `function_name` of a Python file.
    /// Returns `None` for non-Python files, unparseable files, unknown
    /// functions, or variables the model does not cover — callers should then
    /// fall back to their existing resolution.
    pub(crate) fn resolve_variable(
        &mut self,
        file_path: &str,
        function_name: &str,
        variable_name: &str,
    ) -> Option<AstResolution> {
        if !has_python_extension(file_path) {
            return None;
        }
        let function = self.file_facts(file_path)?.functions.get(function_name)?;

        let assignments: Vec<AssignmentFact> = function
            .assignments
            .iter()
            .filter(|fact| fact.target == variable_name)
            .cloned()
            .collect();
        if !assignments.is_empty() {
            return Some(AstResolution::Assignments(assignments));
        }

        let index = function.parameters.iter().position(|name| name == variable_name)?;
        Some(AstResolution::Parameter { index })
    }

    fn file_facts(&mut self, file_path: &str) -> Option<&FileFacts> {
        if !self.file_cache.contains_key(file_path) {
            let facts = parse_file_facts(file_path);
            self.file_cache.insert(file_path.to_string(), facts);
        }
        self.file_cache.get(file_path)?.as_ref()
    }
}

/// Whether AST-grounded Python provenance applies to this file.
pub(crate) fn is_python_source(file_path: &str) -> bool {
    has_python_extension(file_path)
}

/// Assignment facts carried by a single `assignment`/`augmented_assignment`
/// node. Any other node kind carries none — text that merely looks like an
/// assignment (docstrings, string literals) never yields a fact.
pub(crate) fn assignment_facts_for_node(node: Node, source: &[u8]) -> Vec<AssignmentFact> {
    let mut out = Vec::new();
    match node.kind() {
        "assignment" => record_assignment(node, source, &mut out),
        "augmented_assignment" => record_augmented_assignment(node, source, &mut out),
        _ => {}
    }
    out
}

/// Augmented-assignment facts inside a statement wrapper. Plain `assignment`
/// children are deliberately excluded: node collection surfaces those as
/// standalone nodes, so extracting them here as well would double-record.
pub(crate) fn augmented_facts_in_statement(node: Node, source: &[u8]) -> Vec<AssignmentFact> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "augmented_assignment" {
            record_augmented_assignment(child, source, &mut out);
        }
    }
    out
}

fn has_python_extension(file_path: &str) -> bool {
    std::path::Path::new(file_path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "py" | "pyw" | "pyi"))
}

fn parse_file_facts(file_path: &str) -> Option<FileFacts> {
    let source = std::fs::read(file_path).ok()?;
    let mut parser = LanguageParser::new("python").ok()?;
    let tree = parser.parse(&source).ok()?;

    let mut functions = std::collections::BTreeMap::new();
    collect_functions(tree.root_node(), &source, &mut functions);
    Some(FileFacts { functions })
}

/// Preorder walk recording every `def` (sync or async, top-level, nested, or
/// method) by name; the first definition in document order wins.
fn collect_functions(
    node: Node,
    source: &[u8],
    functions: &mut std::collections::BTreeMap<String, FunctionFacts>,
) {
    if node.kind() == "function_definition" {
        record_function(node, source, functions);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_functions(child, source, functions);
    }
}

fn record_function(
    node: Node,
    source: &[u8],
    functions: &mut std::collections::BTreeMap<String, FunctionFacts>,
) {
    let Some(name_node) = node.child_by_field_name("name") else { return };
    let name = get_node_text_slice(&name_node, source).to_string();
    if functions.contains_key(&name) {
        return;
    }

    let parameters = node
        .child_by_field_name("parameters")
        .map(|p| parameter_names(p, source))
        .unwrap_or_default();
    let mut assignments = Vec::new();
    if let Some(body) = node.child_by_field_name("body") {
        collect_assignments(body, source, &mut assignments);
    }
    functions.insert(name, FunctionFacts { parameters, assignments });
}

fn parameter_names(parameters: Node, source: &[u8]) -> Vec<String> {
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(|child| parameter_name(child, source))
        .collect()
}

fn parameter_name(node: Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => Some(get_node_text_slice(&node, source).to_string()),
        "default_parameter" | "typed_default_parameter" => {
            let name = node.child_by_field_name("name")?;
            Some(get_node_text_slice(&name, source).to_string())
        }
        "typed_parameter" | "list_splat_pattern" | "dictionary_splat_pattern" => {
            let mut cursor = node.walk();
            let name = node.named_children(&mut cursor).find(|c| c.kind() == "identifier")?;
            Some(get_node_text_slice(&name, source).to_string())
        }
        _ => None,
    }
}

/// Collect assignment facts within a function body in source order. Nested
/// `def`/`class`/`lambda` scopes are skipped: their locals are not this
/// function's locals.
fn collect_assignments(node: Node, source: &[u8], out: &mut Vec<AssignmentFact>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" | "class_definition" | "lambda" => {}
            "assignment" => record_assignment(child, source, out),
            "augmented_assignment" => record_augmented_assignment(child, source, out),
            "for_statement" => {
                record_for_targets(child, source, out);
                collect_assignments(child, source, out);
            }
            _ => collect_assignments(child, source, out),
        }
    }
}

fn record_assignment(node: Node, source: &[u8], out: &mut Vec<AssignmentFact>) {
    let Some(left) = node.child_by_field_name("left") else { return };
    // A bare annotation (`x: int`) has no right side and assigns nothing.
    let Some(right) = node.child_by_field_name("right") else { return };

    // Chained assignment (`a = b = value`) nests as assignment-in-assignment;
    // every intermediate target receives the innermost value.
    let mut targets = vec![left];
    let mut value = right;
    while value.kind() == "assignment" {
        let Some(inner_left) = value.child_by_field_name("left") else { return };
        let Some(inner_right) = value.child_by_field_name("right") else { return };
        targets.push(inner_left);
        value = inner_right;
    }

    push_target_facts(node, &targets, value, false, source, out);
}

fn record_augmented_assignment(node: Node, source: &[u8], out: &mut Vec<AssignmentFact>) {
    let Some(left) = node.child_by_field_name("left") else { return };
    let Some(right) = node.child_by_field_name("right") else { return };
    push_target_facts(node, &[left], right, true, source, out);
}

fn record_for_targets(node: Node, source: &[u8], out: &mut Vec<AssignmentFact>) {
    let Some(left) = node.child_by_field_name("left") else { return };
    let Some(iterable) = node.child_by_field_name("right") else { return };
    // The loop variable's provenance is the iterable: tainted iterables yield
    // tainted elements, literal collections yield developer-controlled ones.
    push_target_facts(node, &[left], iterable, false, source, out);
}

fn push_target_facts(
    statement: Node,
    targets: &[Node],
    value: Node,
    augmented: bool,
    source: &[u8],
    out: &mut Vec<AssignmentFact>,
) {
    let line = statement.start_position().row + 1;
    let rhs = normalized_text(value, source);
    let literal_collection = is_literal_collection(value);
    for target in targets {
        for name in target_identifiers(*target, source) {
            out.push(AssignmentFact {
                target: name,
                rhs: rhs.clone(),
                line,
                augmented,
                literal_collection,
            });
        }
    }
}

/// Identifier targets of an assignment left side. A subscript target
/// (`d[key] = v`) attributes the value to the container `d` — the container
/// received tainted data, matching the coverage the text scan provided
/// (per-key precision is future work :p ). Attribute targets (`obj.field`) are not
/// yet modeled. Tuple targets conservatively attribute the whole RHS to each
/// plain-identifier element.
fn target_identifiers(node: Node, source: &[u8]) -> Vec<String> {
    match node.kind() {
        "identifier" => vec![get_node_text_slice(&node, source).to_string()],
        "pattern_list" | "tuple_pattern" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .filter(|child| child.kind() == "identifier")
                .map(|child| get_node_text_slice(&child, source).to_string())
                .collect()
        }
        "subscript" => node
            .child_by_field_name("value")
            .filter(|value| value.kind() == "identifier")
            .map(|value| vec![get_node_text_slice(&value, source).to_string()])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// For a mutating method call on a simple variable — `x.append(v)`, `x.add(v)`,
/// `x.extend(v)`, `x.update(v)`, `x.insert(i, v)` — return `(x, args_text)`.
/// Mutating a collection with tainted data taints the collection; callers
/// classify `args_text` to decide whether the mutation carries taint.
pub(crate) fn collection_mutation_target(node: Node, source: &[u8]) -> Option<(String, String)> {
    if node.kind() != "call" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() != "attribute" {
        return None;
    }
    let object = function.child_by_field_name("object")?;
    if object.kind() != "identifier" {
        return None;
    }
    let method_node = function.child_by_field_name("attribute")?;
    const MUTATORS: [&str; 5] = ["append", "add", "extend", "update", "insert"];
    if !MUTATORS.contains(&get_node_text_slice(&method_node, source)) {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let base = get_node_text_slice(&object, source).to_string();
    Some((base, normalized_text(arguments, source)))
}

fn normalized_text(node: Node, source: &[u8]) -> String {
    get_node_text_slice(&node, source).split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A string/number/bool/None literal. F-strings with interpolations are NOT
/// literals: their value embeds arbitrary expressions.
fn is_literal_expr(node: Node) -> bool {
    match node.kind() {
        "integer" | "float" | "true" | "false" | "none" => true,
        "string" => !has_interpolation(node),
        "concatenated_string" | "unary_operator" | "parenthesized_expression" => {
            all_named_children(node, is_literal_expr)
        }
        _ => false,
    }
}

/// A NON-EMPTY list/tuple/set/dict literal whose elements are all literals (or
/// nested literal collections): every possible value is developer-controlled.
/// Empty collections (`[]`, `{}`) are excluded — they carry no values and are
/// typically populated later (e.g. by a tainted subscript write or `.append`),
/// so treating them as safe would suppress that taint.
fn is_literal_collection(node: Node) -> bool {
    match node.kind() {
        "list" | "tuple" | "set" => {
            has_named_children(node)
                && all_named_children(node, |c| is_literal_expr(c) || is_literal_collection(c))
        }
        "dictionary" => {
            has_named_children(node)
                && all_named_children(node, |pair| {
                    pair.kind() == "pair" && all_named_children(pair, is_literal_expr)
                })
        }
        "parenthesized_expression" => all_named_children(node, is_literal_collection),
        _ => false,
    }
}

fn has_named_children(node: Node) -> bool {
    let mut cursor = node.walk();
    let any = node.named_children(&mut cursor).any(|c| c.kind() != "comment");
    any
}

fn all_named_children(node: Node, predicate: impl Fn(Node) -> bool) -> bool {
    let mut cursor = node.walk();
    let all = node.named_children(&mut cursor).filter(|c| c.kind() != "comment").all(&predicate);
    all
}

fn has_interpolation(node: Node) -> bool {
    if node.kind() == "interpolation" {
        return true;
    }
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).any(has_interpolation);
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn staged(content: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("module.py");
        let mut file = std::fs::File::create(&path).expect("create fixture");
        file.write_all(content.as_bytes()).expect("write fixture");
        (dir, path.to_string_lossy().into_owned())
    }

    fn assignments(resolution: AstResolution) -> Vec<AssignmentFact> {
        match resolution {
            AstResolution::Assignments(facts) => facts,
            other => panic!("expected assignments, got {other:?}"),
        }
    }

    #[test]
    fn resolves_multiline_and_annotated_assignments() {
        let (_dir, path) =
            staged("def run():\n    cmd = (\n        input()\n    )\n    other: str = input()\n");
        let mut provenance = PythonAstProvenance::default();

        let cmd = assignments(provenance.resolve_variable(&path, "run", "cmd").unwrap());
        assert_eq!(cmd.len(), 1);
        assert_eq!(cmd[0].rhs, "( input() )");
        assert_eq!(cmd[0].line, 2);

        let other = assignments(provenance.resolve_variable(&path, "run", "other").unwrap());
        assert_eq!(other[0].rhs, "input()");
    }

    #[test]
    fn resolves_augmented_chained_and_tuple_targets() {
        let (_dir, path) = staged(
            "def run():\n    cmd = \"echo\"\n    cmd += input()\n    a = b = input()\n    x, y = input(), \"log\"\n",
        );
        let mut provenance = PythonAstProvenance::default();

        let cmd = assignments(provenance.resolve_variable(&path, "run", "cmd").unwrap());
        assert_eq!(cmd.len(), 2);
        assert!(!cmd[0].augmented);
        assert!(cmd[1].augmented);
        assert_eq!(cmd[1].rhs, "input()");

        let chained = assignments(provenance.resolve_variable(&path, "run", "b").unwrap());
        assert_eq!(chained[0].rhs, "input()");

        let tuple = assignments(provenance.resolve_variable(&path, "run", "x").unwrap());
        assert_eq!(tuple[0].rhs, "input(), \"log\"");
    }

    #[test]
    fn docstring_text_is_not_an_assignment() {
        let (_dir, path) = staged(
            "def run():\n    \"\"\"Usage:\n\n    cmd = input()\n    \"\"\"\n    cmd = \"uptime\"\n",
        );
        let mut provenance = PythonAstProvenance::default();

        let cmd = assignments(provenance.resolve_variable(&path, "run", "cmd").unwrap());
        assert_eq!(cmd.len(), 1);
        assert_eq!(cmd[0].rhs, "\"uptime\"");
        assert_eq!(cmd[0].line, 6);
    }

    #[test]
    fn async_functions_and_for_targets_resolve() {
        let (_dir, path) = staged(
            "async def report():\n    for flag in [\"beta\", \"canary\"]:\n        print(flag)\n",
        );
        let mut provenance = PythonAstProvenance::default();

        let flag = assignments(provenance.resolve_variable(&path, "report", "flag").unwrap());
        assert!(flag[0].literal_collection);
        assert_eq!(flag[0].rhs, "[\"beta\", \"canary\"]");
    }

    #[test]
    fn literal_collections_exclude_fstrings_and_variables() {
        let (_dir, path) = staged(
            "def run():\n    safe = [\"a\", 1, (\"b\",)]\n    unsafe_var = [name]\n    unsafe_fstring = [f\"{name}\"]\n",
        );
        let mut provenance = PythonAstProvenance::default();

        let safe = assignments(provenance.resolve_variable(&path, "run", "safe").unwrap());
        assert!(safe[0].literal_collection);
        let by_var = assignments(provenance.resolve_variable(&path, "run", "unsafe_var").unwrap());
        assert!(!by_var[0].literal_collection);
        let by_fstring =
            assignments(provenance.resolve_variable(&path, "run", "unsafe_fstring").unwrap());
        assert!(!by_fstring[0].literal_collection);
    }

    #[test]
    fn parameters_resolve_by_index_with_annotations_and_defaults() {
        let (_dir, path) = staged(
            "def handler(self, request: dict, timeout: int = 5, *args, **kwargs):\n    pass\n",
        );
        let mut provenance = PythonAstProvenance::default();

        for (name, index) in
            [("self", 0), ("request", 1), ("timeout", 2), ("args", 3), ("kwargs", 4)]
        {
            match provenance.resolve_variable(&path, "handler", name) {
                Some(AstResolution::Parameter { index: found }) => assert_eq!(found, index),
                other => panic!("{name} should resolve as parameter, got {other:?}"),
            }
        }
    }

    #[test]
    fn nested_function_locals_stay_out_of_the_outer_scope() {
        let (_dir, path) =
            staged("def outer():\n    def inner():\n        cmd = input()\n    cmd = \"safe\"\n");
        let mut provenance = PythonAstProvenance::default();

        let outer = assignments(provenance.resolve_variable(&path, "outer", "cmd").unwrap());
        assert_eq!(outer.len(), 1);
        assert_eq!(outer[0].rhs, "\"safe\"");
    }

    #[test]
    fn unknown_shapes_and_non_python_files_yield_none() {
        let (_dir, path) = staged("def run():\n    with open(\"f\") as handle:\n        pass\n");
        let mut provenance = PythonAstProvenance::default();

        assert!(provenance.resolve_variable(&path, "run", "handle").is_none());
        assert!(provenance.resolve_variable(&path, "missing_fn", "handle").is_none());
        assert!(provenance.resolve_variable("module.rb", "run", "handle").is_none());
    }

    #[test]
    fn subscript_target_attributes_value_to_the_container() {
        let (_dir, path) = staged("def run():\n    cfg = {}\n    cfg[\"name\"] = input(\"n: \")\n");
        let mut provenance = PythonAstProvenance::default();

        // `cfg` carries both the `{}` initializer and the tainted subscript write.
        let cfg = assignments(provenance.resolve_variable(&path, "run", "cfg").unwrap());
        assert_eq!(cfg.len(), 2);
        assert_eq!(cfg[0].rhs, "{}");
        assert!(!cfg[0].literal_collection, "empty dict must not be a literal collection");
        assert_eq!(cfg[1].rhs, "input(\"n: \")");
    }

    #[test]
    fn empty_collections_are_not_literal_collections() {
        let (_dir, path) =
            staged("def run():\n    a = []\n    b = {}\n    c = [\"x\"]\n    d = {\"k\": 1}\n");
        let mut provenance = PythonAstProvenance::default();

        for (name, expected) in [("a", false), ("b", false), ("c", true), ("d", true)] {
            let facts = assignments(provenance.resolve_variable(&path, "run", name).unwrap());
            assert_eq!(facts[0].literal_collection, expected, "{name} literal-collection");
        }
    }

    #[test]
    fn collection_mutation_targets_are_recognized() {
        let (_dir, path) = staged(
            "def run():\n    parts = []\n    parts.append(input(\"p: \"))\n    parts.extend(x)\n    other = obj.compute(y)\n",
        );
        let source = std::fs::read(&path).unwrap();
        let mut parser = LanguageParser::new("python").unwrap();
        let tree = parser.parse(&source).unwrap();

        let mut calls = Vec::new();
        collect_calls(tree.root_node(), &mut calls);
        let mutations: Vec<(String, String)> =
            calls.iter().filter_map(|c| collection_mutation_target(*c, &source)).collect();

        // append + extend are mutators; obj.compute is not.
        assert_eq!(mutations.len(), 2);
        assert_eq!(mutations[0], ("parts".to_string(), "(input(\"p: \"))".to_string()));
        assert_eq!(mutations[1].0, "parts");
    }

    fn collect_calls<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
        if node.kind() == "call" {
            out.push(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            collect_calls(child, out);
        }
    }
}
