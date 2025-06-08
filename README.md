# Vulnerability Scanner - Rust Implementation

A fast, efficient vulnerability scanner written in Rust that uses tree-sitter to analyze Python code for security issues.

## Features

- **AST-based analysis**: Uses tree-sitter for accurate parsing of Python code
- **Configurable rules**: JSON-based rule system for different vulnerability types
- **Pattern matching**: Supports wildcards, regex patterns, and exact matching
- **Context-aware**: Analyzes function arguments and AST context for better accuracy
- **Performance**: Written in Rust for speed and memory efficiency
- **Detailed reporting**: Provides file locations, line numbers, and vulnerability summaries

## Dependencies

The scanner uses the following Rust crates:
- `tree-sitter` and `tree-sitter-python` for AST parsing
- `serde` and `serde_json` for JSON rule parsing
- `regex` for pattern matching
- `walkdir` for directory traversal
- `clap` for command-line interface
- `anyhow` for error handling

## Installation

1. Ensure you have Rust installed (https://rustup.rs/)
2. Clone this repository
3. Build the project:

```bash
cargo build --release
```

## Usage

```bash
cargo run -- <root_directory> <language> <rules_file>
```

Or using the built binary:

```bash
./target/release/find_vulns <root_directory> <language> <rules_file>
```

### Parameters

- `<root_directory>`: The directory to scan recursively
- `<language>`: Programming language (currently only "python" is supported)
- `<rules_file>`: JSON file containing vulnerability detection rules

### Example

```bash
cargo run -- ./my_project python rules/python.json
```

## Rule Format

Rules are defined in JSON format with the following structure:

```json
{
  "injection_sinks": [
    {
      "pattern": "*.execute*",
      "finding_type": "sql_injection",
      "conditions": [
        {
          "type": "has_argument",
          "pattern": "*%s*"
        }
      ]
    }
  ],
  "crypto_rules": [
    {
      "pattern": "hashlib.md5",
      "finding_type": "weak_crypto"
    }
  ]
}
```

### Rule Categories

- `injection_sinks`: SQL injection, command injection, etc.
- `crypto_rules`: Weak cryptographic functions
- `path_traversal`: Path traversal vulnerabilities
- `weak_random`: Weak random number generation
- `hardcoded_secrets`: Hardcoded credentials/secrets
- Custom categories can be added

### Pattern Types

1. **Exact match**: `"os.system"`
2. **Wildcard**: `"*.execute*"` (matches any string containing "execute")
3. **Regex**: `"regex:^subprocess\.(run|call)$"`

### Conditions

Rules can include conditions for more precise matching:

- `has_argument`: Check if function has specific arguments
- `in_context`: Context-aware checks (e.g., not in comments)
- `has_parent`: Check parent AST node types

## Output

The scanner provides:

1. **Individual findings**: File path, line number, vulnerability type, and function name
2. **Summary statistics**: Count by vulnerability type
3. **Most vulnerable files**: Files with the highest number of issues
4. **Total count**: Overall vulnerability count

Example output:
```
Starting Scan! -----------------
./app/models.py:42 - sql_injection - cursor.execute
./app/views.py:15 - command_injection - os.system
./utils/crypto.py:8 - weak_crypto - hashlib.md5

Vulnerability Summary -----------------
command_injection: 1 occurrences
sql_injection: 1 occurrences
weak_crypto: 1 occurrences

Most vulnerable files:
./app/models.py: 1 vulnerabilities
./app/views.py: 1 vulnerabilities
./utils/crypto.py: 1 vulnerabilities

Total vulnerabilities found: 3
```

## Comparison with Python Version

The Rust implementation provides:

- **Better performance**: Faster parsing and analysis
- **Memory efficiency**: Lower memory usage for large codebases
- **Type safety**: Compile-time guarantees for correctness
- **Enhanced error handling**: Better error messages and recovery
- **Modern CLI**: Using `clap` for better command-line experience

## Contributing

To add support for new languages:

1. Add the appropriate tree-sitter language dependency to `Cargo.toml`
2. Update the `VulnerabilityScanner::new()` method to handle the new language
3. Update `get_file_extension()` method for the file extension
4. Create rule files for the new language

## License

This project is open source. Please check the license file for details. 


## Roadmap

- Multiples patterns ✅
- Source & sink analysis
- Run scan on all rules
- Run scan on a directory of rules
- Run against specific file