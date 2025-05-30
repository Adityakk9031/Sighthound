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

// Memory-optimized version that returns a string slice instead of owned String
pub fn get_node_text_slice<'a>(node: &tree_sitter::Node, source: &'a [u8]) -> &'a str {
    let start = node.start_byte();
    let end = node.end_byte();
    std::str::from_utf8(&source[start..end]).unwrap_or("")
}

pub fn get_function_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    if let Some(function_node) = node.child_by_field_name("function") {
        return Some(get_node_text(&function_node, source));
    }
    None
}

// Memory-optimized version that returns a string slice
pub fn get_function_name_slice<'a>(node: &tree_sitter::Node, source: &'a [u8]) -> Option<&'a str> {
    if let Some(function_node) = node.child_by_field_name("function") {
        return Some(get_node_text_slice(&function_node, source));
    }
    None
}

// Iterator-based tree traversal that only yields call nodes
pub fn traverse_calls_only(node: tree_sitter::Node) -> impl Iterator<Item = tree_sitter::Node> {
    TreeCallIterator::new(node)
}

struct TreeCallIterator<'a> {
    stack: Vec<tree_sitter::Node<'a>>,
}

impl<'a> TreeCallIterator<'a> {
    fn new(root: tree_sitter::Node<'a>) -> Self {
        Self { stack: vec![root] }
    }
}

impl<'a> Iterator for TreeCallIterator<'a> {
    type Item = tree_sitter::Node<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            // Add children to stack for traversal
            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    self.stack.push(cursor.node());
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
            
            // Only return call nodes
            if node.kind() == "call" {
                return Some(node);
            }
        }
        None
    }
}