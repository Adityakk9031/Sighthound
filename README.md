# Vulnerability Scanner - Rust Implementation

A fast, efficient vulnerability scanner written in Rust that uses tree-sitter to analyze source code for security issues.

## Features

- **AST-based analysis**: Uses tree-sitter for accurate parsing of code
- **Auto-detection mode**: Automatically detects file types and loads appropriate rules
- **Explicit mode**: Specify exact language and rules for targeted scanning
- **Configurable rules**: JSON-based rule system for different vulnerability types
- **Pattern matching**: Supports wildcards, regex patterns, and exact matching
- **Context-aware**: Analyzes function arguments and AST context for better accuracy
- **Performance**: Written in Rust for speed and memory efficiency
- **Detailed reporting**: Provides file locations, line numbers, and vulnerability summaries


## Installation

1. Ensure you have Rust installed (https://rustup.rs/)
2. Clone this repository
3. Build the project:

```bash
cargo build --release
```

## Usage

### Auto-Detection Mode (Recommended)

The scanner automatically detects file types in your project and loads the appropriate rules:

```bash
# Scan current directory with auto-detection
cargo run -- ./my_project

# Or using the built binary
./target/release/find_vulns ./my_project
```

### Explicit Mode

For targeted scanning of specific languages with specific rules:

```bash
cargo run -- <root_directory> <language> <rules_file>

# Or using the built binary
./target/release/find_vulns <root_directory> <language> <rules_file>
```

### Parameters

#### Auto-Detection Mode
- `<root_directory>`: The directory to scan recursively

#### Explicit Mode  
- `<root_directory>`: The directory to scan recursively
- `<language>`: Programming language (python, java, javascript, tsx, html, django)
- `<rules_file>`: Ron file containing vulnerability detection rules

### Examples

```bash
# Auto-detection: scans all supported file types with appropriate rules
cargo run -- ./my_project

# Auto-detection with JSON output
cargo run -- ./my_project --output-format json

# Auto-detection with verbose output
cargo run -- ./my_project --verbose

# Explicit mode: scan only Python files
cargo run -- ./my_project python rules/python/general.ron

# Explicit mode: scan with all Python rules in directory
cargo run -- ./my_project python rules/python

# Single-threaded mode for debugging
cargo run -- ./my_project --single-threaded
```

### Supported File Types

The auto-detection mode supports:
- **Python** (`.py`) - Uses `rules/python/` 
- **Java** (`.java`) - Uses `rules/java/`
- **JavaScript** (`.js`) - Uses `rules/javascript/`
- **TypeScript JSX** (`.tsx`) - Uses `rules/tsx/`
- **HTML** (`.html`) - Uses `rules/html/`

## Rule Format

Rules are defined in Ron format with the following structure:

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

### File Type Targeting

Each rule can specify which file types it applies to:

```ron
file_types: Some((
    extensions: [".py", ".pyw"],
    include_patterns: ["**/models/**", "**/views/**"],
    exclude_patterns: ["**/test/**", "**/migrations/**"],
)),
```

## Output

The scanner provides:

1. **Individual findings**: File path, line number, vulnerability type, and function name
2. **Summary statistics**: Count by vulnerability type
3. **Most vulnerable files**: Files with the highest number of issues
4. **Total count**: Overall vulnerability count

### Auto-Detection Mode Example Output:
```
🚀 Starting Auto-Detection Scan!
📂 Target directory: ./my_project
🔍 Detected languages: python, java, html
📋 Loaded rules for python
📋 Loaded rules for java  
📋 Loaded rules for html
🚀 Scanning 15 python files with 40 rules...
🚀 Scanning 8 java files with 18 rules...
🚀 Scanning 3 html files with 13 rules...
📊 Scanned 26 files total with 71 rules across 3 languages

./src/models.py:42 - sql_injection - cursor.execute
./src/views.py:15 - command_injection - os.system
./static/app.js:8 - xss - innerHTML

Vulnerability Summary -----------------
command_injection: 1 occurrences
sql_injection: 1 occurrences
xss: 1 occurrences

Most vulnerable files:
./src/models.py: 1 vulnerabilities
./src/views.py: 1 vulnerabilities
./static/app.js: 1 vulnerabilities

Total vulnerabilities found: 3
```

### Explicit Mode Example Output:
```
🚀 Starting Explicit Scan (parallel mode)!
📂 Target directory: ./my_project
🔧 Language: python
📋 Rules directory: rules/python
🔍 Running scan with 40 rules

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
- **Auto-detection**: Automatically scans all supported file types

## Contributing

To add support for new languages:

1. Add the appropriate tree-sitter language dependency to `Cargo.toml`
2. Update the `VulnerabilityScanner::new()` method to handle the new language
3. Update `detect_language_from_path()` method for the file extension
4. Create rule files for the new language in `rules/<language>/`

## License

This project is open source. Please check the license file for details. 


## Roadmap

- Multiples patterns ✅
- Source & sink analysis
- Run scan on all rules ✅
- Run scan on a directory of rules ✅
- Run against specific file
- Glob Support ✅
- Tree-sitter support ✅
- Auto-detection mode ✅

## 🧪 Testing

The test organization follows a layered approach for better maintainability:

### Directory Structure

1. **tests/**: Contains all test code
   - **unit/**: Unit tests for individual components
   - **integration/**: Tests for multiple components working together
   - **end_to_end/**: Tests for the entire system

2. **test_fixtures/**: Contains all test data and fixtures
   - **python/**: Python test files for testing Python-specific vulnerabilities
   - **java/**: Java test files for testing Java-specific vulnerabilities
   - **javascript/**: JavaScript test files for testing JavaScript-specific vulnerabilities
   - **rules/**: Test rule files in RON format

3. **test_scripts/**: Contains scripts and utilities for running tests

For more details about testing, see [README-test.md](README-test.md).