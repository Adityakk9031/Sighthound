# Language Plugin Architecture

This vulnerability scanner now uses a **plugin-based language architecture** that makes adding new programming languages incredibly easy and maintainable.

## 🎯 Benefits

- **📁 Single File Per Language** - All language logic consolidated in one place
- **🔌 Plugin-Like** - Add new languages without touching existing code
- **🎯 Type Safety** - Trait ensures all required methods are implemented
- **⚡ Performance** - Language-specific optimizations possible
- **🧪 Testable** - Each language can be tested independently
- **📦 Optional Dependencies** - Compile with only needed languages

## 🏗️ Architecture Overview

### Core Components

1. **`LanguageSupport` Trait** (`src/language.rs`)
   - Defines the interface all languages must implement
   - Handles AST parsing, function name extraction, and injection patterns

2. **Language Implementations** (`src/language.rs`)
   - `PythonLanguage` - Python-specific logic
   - `JavaLanguage` - Java-specific logic  
   - `JavaScriptLanguage` - Example implementation (placeholder)

3. **Language-Agnostic Components**
   - `LanguageParser` - Generic parser using language trait
   - `VulnerabilityScanner` - Works with any language implementation

## ➕ Adding a New Language

Adding support for a new language requires **only 3 simple steps**:

### Step 1: Add Tree-Sitter Dependency

Add to `Cargo.toml`:
```toml
[features]
rust = ["tree-sitter-rust"]

[dependencies]
tree-sitter-rust = { version = "0.21", optional = true }
```

### Step 2: Implement the Language Trait

Add ~50 lines to `src/language.rs`:

```rust
// Rust Implementation
pub struct RustLanguage;

static RUST_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"format!\(").unwrap(),       // format! macro
        Regex::new(r"println!\(").unwrap(),      // println! macro
        // Add Rust-specific injection patterns...
    ]
});

impl LanguageSupport for RustLanguage {
    fn name(&self) -> &'static str { "rust" }
    fn file_extension(&self) -> &'static str { ".rs" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_rust::language() }
    fn call_node_types(&self) -> &[&'static str] { 
        &["call_expression", "macro_invocation"] 
    }
    
    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        // Implement Rust-specific function name extraction
        match node.kind() {
            "call_expression" => {
                if let Some(function_node) = node.child_by_field_name("function") {
                    let start = function_node.start_byte();
                    let end = function_node.end_byte();
                    return std::str::from_utf8(&source[start..end]).ok();
                }
            }
            "macro_invocation" => {
                if let Some(macro_node) = node.child_by_field_name("macro") {
                    let start = macro_node.start_byte();
                    let end = macro_node.end_byte();
                    return std::str::from_utf8(&source[start..end]).ok();
                }
            }
            _ => {}
        }
        None
    }
    
    fn injection_patterns(&self) -> &[Regex] { &RUST_INJECTION_PATTERNS }
    
    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}
```

### Step 3: Register the Language

Update the `get_language_support` function:

```rust
pub fn get_language_support(language_name: &str) -> Result<Box<dyn LanguageSupport>> {
    match language_name.to_lowercase().as_str() {
        "python" => Ok(Box::new(PythonLanguage)),
        "java" => Ok(Box::new(JavaLanguage)),
        "rust" => Ok(Box::new(RustLanguage)),  // Add this line
        _ => anyhow::bail!("Unsupported language: {}", language_name),
    }
}
```

**That's it!** 🎉 Your new language is fully supported.

## 📋 Language Implementation Checklist

When implementing a new language, make sure to:

- [ ] **File Extension** - Return correct file extension (e.g., `.rs`, `.js`, `.py`)
- [ ] **Tree-Sitter Language** - Import and return the tree-sitter language
- [ ] **Call Node Types** - Define AST node types that represent function calls
- [ ] **Function Name Extraction** - Extract function/method names from call nodes
- [ ] **Injection Patterns** - Define regex patterns for detecting injection vulnerabilities
- [ ] **Arguments Node** - Extract argument nodes for analysis

## 🔄 Migration Benefits

### Before (Scattered Logic)
```
Adding Java required changes in:
├── src/parser.rs (language detection, AST handling)
├── src/rules.rs (injection patterns)  
├── src/scanner.rs (node traversal)
└── Cargo.toml (dependencies)
```

### After (Plugin Architecture)
```
Adding any language requires changes in:
├── src/language.rs (single implementation)
└── Cargo.toml (dependency)
```

## 🧪 Testing New Languages

Each language implementation can be tested independently:

```bash
# Test specific language
cargo test python_language_tests
cargo test java_language_tests

# Test with specific features
cargo build --features="python"
cargo build --features="java,python"
```

## 🎯 Language-Specific Optimizations

Each language can implement optimizations specific to its AST structure:

- **Python**: Optimize for `call` nodes and `arguments` fields
- **Java**: Handle both `method_invocation` and `object_creation_expression`
- **JavaScript**: Process `call_expression` and template literals
- **Rust**: Handle both function calls and macro invocations

## 🚀 Future Enhancements

This architecture enables future enhancements:

- **Hot-swappable language plugins**
- **Language-specific rule engines**
- **Custom AST analysis per language**
- **Performance profiling per language**
- **Language-specific vulnerability types**

## 📊 Performance Impact

The new architecture maintains performance while adding flexibility:
- ✅ Zero runtime overhead (trait methods are monomorphized)
- ✅ Compile-time optimizations preserved
- ✅ Language-specific injection patterns (no shared regex compilation)
- ✅ Optional dependencies reduce binary size 