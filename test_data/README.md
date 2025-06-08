
I'll update the README.md with comprehensive details to help new developers understand the project, including all the modern features and clean syntax implementation we've been working with.


Let me create an updated README.md content for you. Since I cannot directly edit the file, I'll provide the complete updated content:

# 🔍 Corgea Greppy - Advanced Vulnerability Scanner

A blazing-fast, multi-language vulnerability scanner built in Rust that uses tree-sitter for accurate AST-based analysis with parallel processing support.

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## 🚀 Features

### **Core Capabilities**
- **🌐 Multi-language Support**: Python, Java, JavaScript with extensible architecture
- **⚡ Parallel Processing**: Automatic CPU core detection with work-stealing parallelism
- **🎯 AST-based Analysis**: Tree-sitter powered for accurate code understanding
- **📊 Smart Filtering**: File type aware analysis with intelligent pre-filtering
- **🔧 Clean Syntax Rules**: Intuitive rule writing without complex wrappers
- **📁 Directory Rule Loading**: Modular rule organization with automatic merging
- **🏊 Parser Pool**: Efficient parser reuse for maximum performance

### **Analysis Features**
- **Context-aware Detection**: Reduces false positives with AST context analysis
- **Pattern Flexibility**: Exact, wildcard, regex, and multi-pattern support
- **Condition System**: Layered conditions for precise vulnerability detection
- **File Type Filtering**: Target specific files and exclude test directories
- **Progress Reporting**: Real-time scan progress with detailed statistics

### **Developer Experience**
- **Rich CLI Interface**: Comprehensive command-line options with help
- **Multiple Output Formats**: Text, JSON, CSV support
- **Detailed Reporting**: File locations, line numbers, vulnerability summaries
- **Extensive Testing**: Comprehensive test suite with 47+ tests
- **Clean Architecture**: Well-organized, documented, and maintainable codebase

## 📦 Installation

### Prerequisites
- **Rust 1.70+**: Install from [rustup.rs](https://rustup.rs/)
- **Git**: For cloning the repository

### Build from Source
```bash
# Clone the repository
git clone https://github.com/corgea/greppy_prototype.git
cd greppy_prototype

# Build in release mode for maximum performance
cargo build --release

# Install globally (optional)
cargo install --path .
```

### Feature-based Installation
```bash
# Install with specific language support
cargo build --release --features "python,java"

# Default includes all languages
cargo build --release  # Includes Python, Java, JavaScript
```

## 🎯 Quick Start

### Basic Usage
```bash
# Scan a directory with rules file
./target/release/find_vulns /path/to/code python rules/python/general.ron

# Scan with rule directory (loads all .ron files)
./target/release/find_vulns /path/to/code java rules/java/

# Output as JSON
./target/release/find_vulns /path/to/code python rules/python/ -o json

# Verbose output with statistics
./target/release/find_vulns /path/to/code python rules/python/ -v
```

### Development Usage
```bash
# Run with cargo (development)
cargo run -- test_data/java java rules/java/general.ron

# Run tests
cargo test

# Run with specific thread count
cargo run -- test_data/python python rules/python/ --threads 4
```

## 📋 Command Line Options

```bash
find_vulns [OPTIONS] <ROOT_DIR> <LANGUAGE> <RULES_PATH>

ARGUMENTS:
    <ROOT_DIR>      Directory to scan for vulnerabilities
    <LANGUAGE>      Programming language (python, java, javascript)
    <RULES_PATH>    Rules file (.ron) or directory containing .ron files

OPTIONS:
    -o, --output-format <FORMAT>    Output format: text, json, csv [default: text]
    -v, --verbose                   Enable verbose output with detailed statistics
    -s, --summary-only              Show only vulnerability summary
        --single-threaded           Disable parallel processing
        --threads <NUMBER>          Number of threads for parallel processing
    -h, --help                      Print help information
```

## 🎨 Rule Writing Guide

### **Clean Syntax (Recommended)**

Our modern clean syntax eliminates the need for `Some()` wrappers while maintaining full optionality:

```ron
{
    injection_sinks: [
        (
            pattern: "cursor.execute",
            finding_type: "sql_injection",
            severity: "high",
            confidence: "medium",
            conditions: [
                (type: "not_literal", argument_position: 0),
                (type: "has_argument", patterns: ["*user*", "*input*"]),
            ],
            file_types: (
                extensions: [".py"],
                exclude_patterns: ["*test*"],
            ),
        ),
    ],
    
    deserialization: [
        (
            patterns: [
                "pickle.loads",
                "pickle.load",
                "cPickle.loads"
            ],
            finding_type: "insecure_deserialization",
            severity: "critical",
            confidence: "high",
        ),
    ],
}
```

### **Rule Categories**

| Category | Purpose | Examples |
|----------|---------|----------|
| `injection_sinks` | SQL/Command injection | `cursor.execute`, `os.system` |
| `deserialization` | Unsafe deserialization | `pickle.loads`, `readObject` |
| `crypto_rules` | Weak cryptography | `hashlib.md5`, `DES` |
| `path_traversal` | Directory traversal | `os.path.join` |
| `weak_random` | Weak randomness | `random.random` |
| `hardcoded_secrets` | Embedded credentials | API keys, passwords |
| **Custom categories** | Your specific needs | Any category name |

### **Pattern Types**

```ron
// Exact match
pattern: "eval"

// Wildcard patterns  
pattern: "*.execute"      // Good: specific enough
pattern: "*clipboard*"    // OK: targets functionality

// Regex patterns
pattern: "regex:^(eval|exec)$"

// Multiple patterns (recommended for related functions)
patterns: [
    "hashlib.md5",
    "hashlib.sha1", 
    "Crypto.Hash.MD5"
]
```

### **Essential Conditions**

```ron
conditions: [
    // Exclude hardcoded values (major false positive reducer!)
    (type: "not_literal", argument_position: 0),
    
    // Look for suspicious patterns
    (type: "has_argument", patterns: ["*user*", "*input*", "*request*"]),
    
    // Exclude sanitized input
    (type: "argument_not_sanitized", patterns: ["*escape*", "*quote*"]),
    
    // Exclude comments and strings
    (type: "in_context", not_in: ["comment", "string_literal"]),
    
    // Context awareness
    (type: "not_in_protective_context"),
]
```

### **File Type Filtering**

```ron
file_types: (
    extensions: [".py", ".pyw"],
    include_patterns: ["*models*", "*views*", "*controllers*"],
    exclude_patterns: ["*test*", "*example*", "*demo*"],
)
```

### **Confidence Levels**

- **`high`** (95%+ accuracy): Specific patterns with multiple conditions
- **`medium`** (80-95% accuracy): Broader patterns with contextual filtering  
- **`low`** (60-80% accuracy): Experimental patterns, expect false positives

## 🏗️ Project Architecture

### **Module Structure**
```
src/
├── main.rs              # Application entry point
├── lib.rs               # Public API exports  
├── cli.rs               # Command-line interface
├── rules.rs             # Rules engine with clean syntax
├── language.rs          # Multi-language support framework
├── parser.rs            # AST navigation utilities
└── scanner/
    ├── mod.rs           # Scanner module exports
    ├── core.rs          # Main vulnerability scanner
    ├── analyzers.rs     # File type analysis & filtering
    ├── prefilter.rs     # File discovery & filtering
    ├── pool.rs          # Parser pool management
    └── types.rs         # Shared data structures
```

### **Key Components**

1. **Rules Engine** (`rules.rs`)
   - Clean syntax with custom deserializers
   - Pattern matching engine
   - Condition evaluation system
   - File type filtering

2. **Language Support** (`language.rs`)
   - Trait-based language abstraction
   - Tree-sitter parser management
   - Language detection

3. **Scanner Core** (`scanner/core.rs`)
   - Parallel processing coordination
   - Rule application and filtering
   - Finding aggregation

4. **Parser Pool** (`scanner/pool.rs`)
   - Thread-safe parser reuse
   - Automatic scaling
   - Performance optimization

## 🧪 Testing

### **Run Tests**
```bash
# Run all tests
cargo test

# Run specific test module
cargo test integration_tests

# Run with verbose output
cargo test -- --nocapture

# Run Java rules tests
bash test_data/test_scripts/test_java_rules.sh
```

### **Test Structure**
```
tests/
├── integration_tests.rs              # End-to-end testing
├── pattern_matching_tests.rs         # Rule engine testing  
├── django_xss_prevention_tests.rs    # Framework-specific tests
├── file_pattern_tests.rs             # File filtering tests
├── rule_deserialization_tests.rs     # Clean syntax tests
└── directory_loading_tests.rs        # Rule loading tests

test_data/
├── java/                # Java test files
├── python/              # Python test files  
├── test_rules/          # Rule test cases
└── test_scripts/        # Test automation scripts
```

## 📊 Performance

### **Benchmarks**
- **Parallel Processing**: Automatic CPU core utilization
- **Parser Pool**: Eliminates parser recreation overhead
- **Smart Filtering**: Pre-filters files before expensive parsing
- **Memory Efficient**: Streaming processing with bounded memory

### **Optimization Features**
- Link-time optimization (LTO) in release builds
- Maximum compiler optimization (`opt-level = 3`)
- Efficient AST traversal with early termination
- Intelligent rule caching and filtering

## 🔧 Development

### **Adding Language Support**

1. **Add dependency** to `Cargo.toml`:
```toml
tree-sitter-mylang = { version = "0.21", optional = true }

[features]
mylang = ["tree-sitter-mylang"]
```

2. **Implement language support** in `language.rs`:
```rust
pub struct MyLangSupport;

impl LanguageSupport for MyLangSupport {
    fn create_parser(&self) -> tree_sitter::Parser {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(tree_sitter_mylang::language()).unwrap();
        parser
    }
    
    fn language(&self) -> tree_sitter::Language {
        tree_sitter_mylang::language()
    }
    
    fn file_extensions(&self) -> &[&str] {
        &[".mylang"]
    }
}
```

3. **Create rules** in `rules/mylang/`:
```
rules/mylang/
├── general.ron          # General vulnerability rules
├── framework.ron        # Framework-specific rules
└── crypto.ron          # Cryptographic rules
```

### **Contributing Guidelines**

1. **Code Style**: Follow Rust conventions with `cargo fmt`
2. **Testing**: Add tests for new features
3. **Documentation**: Update documentation for API changes  
4. **Performance**: Consider performance impact of changes
5. **Compatibility**: Maintain backward compatibility when possible

## 📈 Output Examples

### **Text Output**
```
🚀 Starting Corgea Greppy Scan (parallel mode)!
📂 Target directory: test_data/java
🔧 Language: java
📋 Rules file: rules/java/general.ron
🔍 Running scan with 18 rules

test_data/java/VulnerableController.java:17 - insecure_deserialization - readObject
test_data/java/SQLService.java:15 - sql_injection - execute

Vulnerability Summary -----------------
insecure_deserialization: 1 occurrences
sql_injection: 1 occurrences

Most vulnerable files:
test_data/java/VulnerableController.java: 1 vulnerabilities
test_data/java/SQLService.java: 1 vulnerabilities

Total vulnerabilities found: 2
```

### **JSON Output**
```json
{
  "scan_info": {
    "target_directory": "test_data/java",
    "language": "java", 
    "rules_count": 18,
    "files_scanned": 6
  },
  "findings": [
    {
      "file": "test_data/java/VulnerableController.java",
      "line": 17,
      "function": "readObject", 
      "finding_type": "insecure_deserialization",
      "code": "Object obj = ois.readObject();"
    }
  ],
  "summary": {
    "total_vulnerabilities": 2,
    "by_type": {
      "insecure_deserialization": 1,
      "sql_injection": 1
    }
  }
}
```

## 🛣️ Roadmap

### **Completed ✅**
- [x] Multi-language support (Python, Java, JavaScript)
- [x] Clean syntax implementation
- [x] Parallel processing with parser pools
- [x] Directory-based rule loading
- [x] Comprehensive testing suite
- [x] File type filtering and smart pre-filtering
- [x] Multiple output formats

### **In Progress 🔄**
- [ ] Machine learning integration for false positive reduction
- [ ] Web dashboard for scan results
- [ ] IDE plugins and integrations
- [ ] Custom condition plugin system

### **Planned 🎯**
- [ ] Distributed scanning capabilities
- [ ] Advanced control flow analysis
- [ ] Framework-specific rule libraries
- [ ] Automatic rule generation from CVE databases
- [ ] SARIF output format support

## 📝 Migration from Legacy Syntax

If you have existing rules with `Some()` wrappers, they still work! But we recommend migrating to clean syntax:

```ron
// Legacy (still works)
injection_sinks: Some([
    (
        pattern: "eval",
        finding_type: Some("code_injection"),
        conditions: Some([...]),
    ),
])

// Clean syntax (recommended)
injection_sinks: [
    (
        pattern: "eval",
        finding_type: "code_injection", 
        conditions: [...],
    ),
]
```

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines and feel free to:

- Report bugs and request features via GitHub issues
- Submit pull requests for bug fixes and enhancements
- Improve documentation and examples
- Add support for new languages
- Create rule libraries for specific frameworks

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Tree-sitter team** for the excellent parsing framework
- **Rust community** for the amazing ecosystem
- **Security researchers** for vulnerability detection techniques
- **Contributors** who help make this project better

---

**Built with ❤️ by the Corgea Team**

For more information, visit our [documentation](docs/) or check out the [examples](examples/) directory.

This updated README provides comprehensive information for new developers while highlighting all the modern features and clean architecture of the vulnerability scanner. It includes practical examples, clear documentation, and guidance for both usage and development.
