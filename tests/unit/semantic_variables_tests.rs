use sighthound::parser::LanguageParser;
use sighthound::scanner::utils::{AstUtils, VariableType};
use tree_sitter::Node;

#[cfg(test)]
mod semantic_variables_tests {
    use super::*;

    fn find_node_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = find_node_of_kind(child, kind) {
                return Some(found);
            }
        }
        None
    }

    fn parse_python(source: &str) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = LanguageParser::new("python").expect("python support available");
        let bytes = source.as_bytes().to_vec();
        let tree = parser.parse(&bytes).expect("parse should succeed");
        (tree, bytes)
    }

    #[test]
    fn assignment_yields_target_and_source_variables() {
        let (tree, source) = parse_python("user_input = get_value(raw_data)");
        let node = find_node_of_kind(tree.root_node(), "assignment").expect("expected assignment");

        let vars = AstUtils::extract_semantic_variables(&node, &source);

        let target = vars
            .iter()
            .find(|v| matches!(v.var_type, VariableType::AssignmentTarget))
            .expect("expected an assignment target");
        assert_eq!(target.name, "user_input");

        let source_names: Vec<&str> = vars
            .iter()
            .filter(|v| matches!(v.var_type, VariableType::Source))
            .map(|v| v.name.as_str())
            .collect();
        assert!(source_names.contains(&"get_value"));
        assert!(source_names.contains(&"raw_data"));
    }

    #[test]
    fn call_yields_function_argument_variables() {
        let (tree, source) = parse_python("os.system(cmd)");
        let node = find_node_of_kind(tree.root_node(), "call").expect("expected call node");

        let vars = AstUtils::extract_semantic_variables(&node, &source);

        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, "cmd");
        assert!(matches!(vars[0].var_type, VariableType::FunctionArgument));
    }

    #[test]
    fn call_with_only_string_literal_argument_yields_no_variables() {
        let (tree, source) = parse_python("os.system(\"ls -la\")");
        let node = find_node_of_kind(tree.root_node(), "call").expect("expected call node");

        let vars = AstUtils::extract_semantic_variables(&node, &source);

        assert!(vars.is_empty());
    }

    #[test]
    fn unhandled_node_kind_yields_no_variables() {
        let (tree, source) = parse_python("user_input = get_value(request)");
        let node = find_node_of_kind(tree.root_node(), "identifier").expect("expected identifier");

        let vars = AstUtils::extract_semantic_variables(&node, &source);

        assert!(vars.is_empty());
    }
}
