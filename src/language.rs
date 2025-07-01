use anyhow::Result;
use tree_sitter::{Language, Node};
use crate::parser::get_node_text_slice;

pub trait LanguageSupport: Send + Sync {
    fn name(&self) -> &'static str;
    fn file_extension(&self) -> &'static str;
    fn tree_sitter_language(&self) -> Language;
    fn call_node_types(&self) -> &[&'static str];
    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str>;
    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>>;
}

pub fn get_language_support(language_name: &str) -> Result<Box<dyn LanguageSupport>> {
    match language_name.to_lowercase().as_str() {
        #[cfg(feature = "python")]
        "python" => Ok(Box::new(PythonLanguage)),
        #[cfg(feature = "java")]
        "java" => Ok(Box::new(JavaLanguage)),
        #[cfg(feature = "javascript")]
        "javascript" | "js" => Ok(Box::new(JavaScriptLanguage)),
        #[cfg(feature = "tsx")]
        "tsx" | "typescript-jsx" => Ok(Box::new(TSXLanguage)),
        #[cfg(feature = "html")]
        "html" => Ok(Box::new(HTMLLanguage)),
        #[cfg(feature = "django")]
        "django" | "django-html" => Ok(Box::new(DjangoTemplateLanguage)),
        _ => {
            let mut supported = Vec::new();
            #[cfg(feature = "python")]
            supported.push("python");
            #[cfg(feature = "java")]
            supported.push("java");
            #[cfg(feature = "javascript")]
            supported.push("javascript");
            #[cfg(feature = "tsx")]
            supported.push("tsx");
            #[cfg(feature = "html")]
            supported.push("html");
            #[cfg(feature = "django")]
            supported.push("django");

            anyhow::bail!(
                "Unsupported language: {}. Supported languages: {}",
                language_name,
                supported.join(", ")
            )
        }
    }
}

// Python Implementation
#[cfg(feature = "python")]
pub struct PythonLanguage;

#[cfg(feature = "python")]
impl LanguageSupport for PythonLanguage {
    fn name(&self) -> &'static str { "python" }
    fn file_extension(&self) -> &'static str { ".py" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_python::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] { &["call"] }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        node.child_by_field_name("function")
            .map(|child| get_node_text_slice(&child, source))
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}

// Java Implementation
#[cfg(feature = "java")]
pub struct JavaLanguage;

#[cfg(feature = "java")]
impl LanguageSupport for JavaLanguage {
    fn name(&self) -> &'static str { "java" }
    fn file_extension(&self) -> &'static str { ".java" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_java::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["method_invocation", "object_creation_expression"]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "method_invocation" => {
                node.child_by_field_name("name")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "object_creation_expression" => {
                node.child_by_field_name("type")
                    .map(|child| get_node_text_slice(&child, source))
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}

// JavaScript Implementation
#[cfg(feature = "javascript")]
pub struct JavaScriptLanguage;

#[cfg(feature = "javascript")]
impl LanguageSupport for JavaScriptLanguage {
    fn name(&self) -> &'static str { "javascript" }
    fn file_extension(&self) -> &'static str { ".js" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_javascript::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["call_expression", "new_expression"]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "call_expression" => {
                node.child_by_field_name("function")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "new_expression" => {
                node.child_by_field_name("constructor")
                    .map(|child| get_node_text_slice(&child, source))
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}

// TSX Implementation
#[cfg(feature = "tsx")]
pub struct TSXLanguage;

#[cfg(feature = "tsx")]
impl LanguageSupport for TSXLanguage {
    fn name(&self) -> &'static str { "tsx" }
    fn file_extension(&self) -> &'static str { ".tsx" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_typescript::LANGUAGE_TSX.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["call_expression", "new_expression", "jsx_expression", "jsx_attribute"]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "jsx_attribute" => {
                node.child_by_field_name("name")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "call_expression" => {
                node.child_by_field_name("function")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "new_expression" => {
                node.child_by_field_name("constructor")
                    .map(|child| get_node_text_slice(&child, source))
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
            .or_else(|| node.child_by_field_name("value"))
    }
}

// HTML Implementation
#[cfg(feature = "html")]
pub struct HTMLLanguage;

#[cfg(feature = "html")]
impl LanguageSupport for HTMLLanguage {
    fn name(&self) -> &'static str { "html" }
    fn file_extension(&self) -> &'static str { ".html" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_html::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["attribute", "start_tag", "script_element", "element"]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "attribute" => {
                node.child_by_field_name("name")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "start_tag" | "element" => {
                node.child_by_field_name("name")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "script_element" => {
                Some("script")
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        if node.kind() == "attribute" {
            if let Some(value_node) = node.child_by_field_name("value") {
                return Some(value_node);
            }

            // Fallback: look for value-like children
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    match child.kind() {
                        "attribute_value" | "quoted_attribute_value" | "string" => {
                            return Some(child);
                        }
                        _ => continue,
                    }
                }
            }
        }

        node.child_by_field_name("value")
    }
}

// Django Template Implementation
#[cfg(feature = "django")]
pub struct DjangoTemplateLanguage;

#[cfg(feature = "django")]
impl LanguageSupport for DjangoTemplateLanguage {
    fn name(&self) -> &'static str { "django" }
    fn file_extension(&self) -> &'static str { ".html" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_html::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["attribute", "text", "script_element"]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "text" => {
                let text = get_node_text_slice(node, source);

                // Check for Django template patterns (return static strings for consistent lifetimes)
                if text.contains("|safe") {
                    Some("|safe")
                } else if text.contains("|mark_safe") {
                    Some("|mark_safe")
                } else if text.contains("{% autoescape off %}") {
                    Some("{% autoescape off %}")
                } else if text.contains("{{") && text.contains("}}") {
                    Some("{{")}
                else if text.contains("{% include") {
                    Some("{% include")
                } else if text.contains("{{") || text.contains("{%") {
                    Some("django_template")
                } else {
                    None
                }
            }
            "attribute" => {
                node.child_by_field_name("name")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "script_element" => {
                Some("script")
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        match node.kind() {
            "text" => Some(*node),
            "attribute" => {
                if let Some(value_node) = node.child_by_field_name("value") {
                    return Some(value_node);
                }
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        match child.kind() {
                            "attribute_value" | "quoted_attribute_value" | "string" => {
                                return Some(child);
                            }
                            _ => continue,
                        }
                    }
                }
                None
            }
            _ => node.child_by_field_name("value")
        }
    }
}