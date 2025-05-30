use anyhow::{Context, Result};
use tree_sitter::{Parser as TSParser, Tree};

pub struct LanguageParser {
    parser: TSParser,
}

impl LanguageParser {
    pub fn new(language_name: &str) -> Result<Self> {
        if language_name.to_lowercase() != "python" {
            anyhow::bail!("This scanner currently supports only Python");
        }

        let language = tree_sitter_python::language();
        let mut parser = TSParser::new();
        parser.set_language(&language).context("Failed to set language")?;

        Ok(Self { parser })
    }

    pub fn parse(&mut self, source: &[u8]) -> Result<Tree> {
        self.parser.parse(source, None).context("Failed to parse file")
    }

    pub fn get_file_extension(&self, language_name: &str) -> &str {
        match language_name.to_lowercase().as_str() {
            "python" => ".py",
            _ => "",
        }
    }
}

pub fn get_node_text(node: &tree_sitter::Node, source: &[u8]) -> String {
    let start = node.start_byte();
    let end = node.end_byte();
    String::from_utf8_lossy(&source[start..end]).to_string()
}

pub fn get_function_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    if let Some(function_node) = node.child_by_field_name("function") {
        return Some(get_node_text(&function_node, source));
    }
    None
}

pub fn traverse_node<'a>(node: tree_sitter::Node<'a>) -> Vec<tree_sitter::Node<'a>> {
    let mut nodes = vec![node];
    let mut cursor = node.walk();

    if cursor.goto_first_child() {
        loop {
            nodes.extend(traverse_node(cursor.node()));
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    nodes
} 