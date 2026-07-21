use crate::language::LanguageSupport;
use crate::parser::get_node_text;
use crate::rules::Condition;
use crate::rules::{is_literal_node, match_any_pattern, match_pattern};

/// Check if all AST conditions are satisfied for a node
pub fn check_ast_conditions(
    conditions: &[Condition],
    node: &tree_sitter::Node,
    source: &[u8],
    language_support: &dyn LanguageSupport,
) -> bool {
    conditions
        .iter()
        .all(|condition| check_single_condition(node, source, condition, language_support))
}

/// Check a single AST condition
pub fn check_single_condition(
    node: &tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
    language_support: &dyn LanguageSupport,
) -> bool {
    match condition.condition_type.as_deref().unwrap_or("") {
        "has_argument" => check_has_argument_condition(node, source, condition, language_support),
        "in_context" => {
            if condition.not_in.is_some() {
                check_in_context_condition(node, condition)
            } else {
                evaluate_field_condition(node, source, condition)
            }
        }
        "has_parent" => check_has_parent_condition(node, condition),
        "not_literal" => check_not_literal_condition(node, condition, language_support),
        "has_ancestor" => check_has_ancestor_condition(node, condition),
        "argument_not_sanitized" => {
            check_argument_not_sanitized_condition(node, source, condition, language_support)
        }
        "has_sibling_pattern" => check_has_sibling_pattern_condition(node, source, condition),
        "ruby_unsafe_command_injection" => {
            check_ruby_unsafe_command_injection(node, source, language_support)
        }
        _ => evaluate_field_condition(node, source, condition),
    }
}

/// Check if function has an argument matching the condition
pub fn check_has_argument_condition(
    node: &tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
    language_support: &dyn LanguageSupport,
) -> bool {
    if let Some(args_node) = language_support.get_arguments_node(node) {
        // If specific position is specified, check only that argument
        if let Some(position) = condition.argument_position {
            if let Some(arg) = args_node.named_child(position as u32) {
                return check_argument_matches(arg, source, condition);
            }
            return false;
        }

        // Otherwise check all arguments
        for i in 0..args_node.named_child_count() {
            if let Some(arg) = args_node.named_child(i as u32) {
                if check_argument_matches(arg, source, condition) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if an argument node matches the given condition
pub fn check_argument_matches(
    arg: tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
) -> bool {
    let arg_text = get_node_text(&arg, source);

    // Check node type if specified
    if let Some(expected_type) = &condition.node_type {
        if arg.kind() != expected_type {
            return false;
        }
    }

    // Check pattern(s)
    if let Some(pattern) = &condition.pattern {
        return match_pattern(pattern, &arg_text);
    }

    if let Some(patterns) = &condition.patterns {
        return match_any_pattern(patterns, &arg_text);
    }

    true
}

/// Check if node is in a specific context (e.g., not in comments/strings)
pub fn check_in_context_condition(node: &tree_sitter::Node, condition: &Condition) -> bool {
    if let Some(not_in) = &condition.not_in {
        if let Some(parent) = node.parent() {
            if not_in.contains(&"comment".to_string()) && parent.kind() == "comment" {
                return false;
            }
            if not_in.contains(&"string".to_string()) && parent.kind() == "string" {
                return false;
            }
        }
    }
    true
}

/// Check if node has a specific parent type
pub fn check_has_parent_condition(node: &tree_sitter::Node, condition: &Condition) -> bool {
    if let Some(parent_type) = &condition.parent_type {
        if let Some(parent) = node.parent() {
            return parent.kind() == parent_type;
        }
        return false;
    }
    true
}

/// Check if arguments are not literal values
pub fn check_not_literal_condition(
    node: &tree_sitter::Node,
    condition: &Condition,
    language_support: &dyn LanguageSupport,
) -> bool {
    if let Some(args_node) = language_support.get_arguments_node(node) {
        if let Some(position) = condition.argument_position {
            if let Some(arg) = args_node.named_child(position as u32) {
                return !is_literal_node(&arg);
            }
        } else {
            // Check if any argument is not literal
            for i in 0..args_node.named_child_count() {
                if let Some(arg) = args_node.named_child(i as u32) {
                    if !is_literal_node(&arg) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Check if node has specific ancestor types
pub fn check_has_ancestor_condition(node: &tree_sitter::Node, condition: &Condition) -> bool {
    if let Some(ancestor_types) = &condition.ancestor_types {
        let mut current = node.parent();
        let mut depth = 0;

        while let Some(parent) = current {
            if depth > 20 {
                // Limit search depth
                break;
            }

            if ancestor_types.contains(&parent.kind().to_string()) {
                return true;
            }

            current = parent.parent();
            depth += 1;
        }
    }
    false
}

/// Check if arguments are not sanitized
pub fn check_argument_not_sanitized_condition(
    node: &tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
    language_support: &dyn LanguageSupport,
) -> bool {
    if let Some(sanitizer_patterns) = &condition.patterns {
        if let Some(args_node) = language_support.get_arguments_node(node) {
            for i in 0..args_node.named_child_count() {
                if let Some(arg) = args_node.named_child(i as u32) {
                    let arg_text = get_node_text(&arg, source);

                    // Check if argument contains any sanitization patterns
                    for sanitizer in sanitizer_patterns {
                        if match_pattern(sanitizer, &arg_text) {
                            return false; // Found sanitization, so condition fails
                        }
                    }
                }
            }
        }
        return true; // No sanitization found
    }
    true
}

/// Check if node has siblings matching patterns
pub fn check_has_sibling_pattern_condition(
    node: &tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
) -> bool {
    if let Some(patterns) = &condition.patterns {
        if let Some(parent) = node.parent() {
            let mut cursor = parent.walk();
            if cursor.goto_first_child() {
                loop {
                    let sibling = cursor.node();
                    if sibling != *node {
                        let sibling_text = get_node_text(&sibling, source);
                        if match_any_pattern(patterns, &sibling_text) {
                            return true;
                        }
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
    }
    false
}

fn clean_ruby_string(s: String) -> String {
    let mut val = s.trim().to_string();
    if ((val.starts_with('"') && val.ends_with('"'))
        || (val.starts_with('\'') && val.ends_with('\'')))
        && val.len() >= 2
    {
        val = val[1..val.len() - 1].to_string();
    }
    if val.starts_with(':') {
        val = val[1..].to_string();
    }
    val.trim().to_string()
}

fn is_shell_executable(text: &str) -> bool {
    let cleaned = text.trim();
    if cleaned.is_empty() {
        return false;
    }
    let std_path = cleaned.replace('\\', "/");
    let filename = std_path.rsplit('/').next().unwrap_or(cleaned).to_ascii_lowercase();
    let name_without_ext = filename.strip_suffix(".exe").unwrap_or(&filename);

    matches!(
        name_without_ext,
        "sh" | "bash"
            | "cmd"
            | "powershell"
            | "pwsh"
            | "zsh"
            | "ksh"
            | "csh"
            | "tcsh"
            | "fish"
            | "dash"
            | "ash"
    )
}

fn get_ruby_callee_name(
    node: &tree_sitter::Node,
    source: &[u8],
    language_support: &dyn LanguageSupport,
) -> String {
    if let Some(method_name) = language_support.get_function_name(node, source) {
        if let Some(receiver_node) = node.child_by_field_name("receiver") {
            let receiver_text = get_node_text(&receiver_node, source);
            return format!("{}.{}", receiver_text.trim(), method_name.trim());
        }
        return method_name.trim().to_string();
    }
    let node_text = get_node_text(node, source);
    let callee =
        node_text.split('(').next().unwrap_or(&node_text).split_whitespace().next().unwrap_or("");
    callee.trim().to_string()
}

/// Check if a Ruby call's arguments structure represents an unsafe command execution.
/// A Ruby call (system, exec, etc.) is safe if it has more than one argument
/// or if it has a single argument which is an array literal or a splatted array literal.
/// Callee signatures like IO.popen and Open3.pipeline are handled according to their specific Ruby semantics.
/// Returns true if the call is UNSAFE (i.e. we should match/flag it).
pub fn check_ruby_unsafe_command_injection(
    node: &tree_sitter::Node,
    source: &[u8],
    language_support: &dyn LanguageSupport,
) -> bool {
    if language_support.name() != "ruby" {
        return true;
    }
    if let Some(args_node) = language_support.get_arguments_node(node) {
        let mut cmd_args = Vec::new();
        for i in 0..args_node.named_child_count() {
            if let Some(child) = args_node.named_child(i as u32) {
                cmd_args.push(child);
            }
        }

        // 1. Filter out environment hash at the beginning (index 0) if there are other arguments
        if !cmd_args.is_empty()
            && (cmd_args[0].kind() == "hash" || cmd_args[0].kind() == "hash_literal")
            && cmd_args.len() > 1
        {
            cmd_args.remove(0);
        }

        // 2. Filter out options/keyword arguments/hash splats at the end
        while !cmd_args.is_empty() {
            let last_kind = cmd_args[cmd_args.len() - 1].kind();
            if last_kind == "hash"
                || last_kind == "hash_literal"
                || last_kind == "pair"
                || last_kind == "keyword_argument"
                || last_kind == "hash_splat_argument"
            {
                cmd_args.pop();
            } else {
                break;
            }
        }

        let callee = get_ruby_callee_name(node, source, language_support);

        // Special handling for IO.popen / popen:
        // IO.popen([env,] cmd, mode = 'r', opt = {})
        // The first argument after env (cmd_args[0]) is the command. Second argument is mode, NOT a command arg!
        // IO.popen("ls -la", "r") passes a single string to shell -> UNSAFE.
        // IO.popen(["ls", params[:cmd]], "r") passes an array -> SAFE (bypasses shell).
        if callee == "IO.popen" || callee == "popen" {
            if !cmd_args.is_empty() {
                let arg = &cmd_args[0];
                if arg.kind() == "array" {
                    return false; // Safe: array argument
                }
                if arg.kind() == "splat_argument" {
                    for i in 0..arg.named_child_count() {
                        if let Some(child) = arg.named_child(i as u32) {
                            if child.kind() == "array" {
                                return false; // Safe: splatted array argument
                            }
                        }
                    }
                }
            }
            return true; // Single-string command passed to IO.popen is UNSAFE
        }

        // Special handling for Open3.pipeline*:
        // Open3.pipeline(cmd1, cmd2, ..., opts)
        // Each positional argument is a command in a pipeline.
        // If any command argument is a string (e.g. Open3.pipeline("ls", params[:cmd])), each is executed via shell -> UNSAFE.
        // If ALL command arguments are arrays or splatted arrays, it is SAFE.
        if callee.starts_with("Open3.pipeline") || callee.starts_with("pipeline") {
            if cmd_args.is_empty() {
                return true;
            }
            let all_arrays = cmd_args.iter().all(|arg| {
                if arg.kind() == "array" {
                    return true;
                }
                if arg.kind() == "splat_argument" {
                    for i in 0..arg.named_child_count() {
                        if let Some(child) = arg.named_child(i as u32) {
                            if child.kind() == "array" {
                                return true;
                            }
                        }
                    }
                }
                false
            });
            return !all_arrays;
        }

        let count = cmd_args.len();
        if count > 1 {
            let first_text = clean_ruby_string(get_node_text(&cmd_args[0], source));
            if is_shell_executable(&first_text) {
                for arg_node in cmd_args.iter().skip(1) {
                    let arg_text = clean_ruby_string(get_node_text(arg_node, source));
                    if arg_text == "-c" || arg_text == "/c" || arg_text == "/C" || arg_text == "-C"
                    {
                        return true; // Explicit shell execution: UNSAFE
                    }
                }
            }
            return false; // Safe: multi-argument form bypassed the shell
        }
        if count == 1 {
            let arg = &cmd_args[0];
            if arg.kind() == "array" {
                return false; // Safe: single array literal argument bypassed the shell
            }
            if arg.kind() == "splat_argument" {
                // Check if splatted argument is an array literal
                let mut has_array_child = false;
                for i in 0..arg.named_child_count() {
                    if let Some(child) = arg.named_child(i as u32) {
                        if child.kind() == "array" {
                            has_array_child = true;
                            break;
                        }
                    }
                }
                if has_array_child {
                    return false; // Safe: splatted array literal bypassed the shell
                }
            }
        }
    }
    true // Unsafe: likely single-string command that will invoke the shell
}

/// Helper function to evaluate generic conditions based on field, operator, and value.
pub fn evaluate_field_condition(
    node: &tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
) -> bool {
    let node_text = get_node_text(node, source);
    match condition.field.as_str() {
        "pattern" => match condition.operator.as_str() {
            "not_contains" => !node_text.contains(&condition.value),
            "contains" => node_text.contains(&condition.value),
            _ => false,
        },
        "context" => {
            let context_text = get_context_text(node, source);
            match condition.operator.as_str() {
                "not_contains" => !context_text.contains(&condition.value),
                "contains" => context_text.contains(&condition.value),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Helper function to extract context text (surrounding function or method node) for a given AST node.
pub fn get_context_text(node: &tree_sitter::Node, source: &[u8]) -> String {
    let mut current = *node;
    while let Some(parent) = current.parent() {
        let kind = parent.kind();
        if kind.contains("function") || kind.contains("method") || kind.contains("arrow") {
            return get_node_text(&parent, source);
        }
        current = parent;
    }
    // Fallback to the parent node or the node itself
    if let Some(parent) = node.parent() {
        get_node_text(&parent, source)
    } else {
        get_node_text(node, source)
    }
}
