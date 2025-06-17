![Sighthound Banner](assets/logo.png)

# Sighthound

A blazing fast, and precise scanner to find source code for security issues.

## Features

- **Performance**: Written in Rust for speed and memory efficiency
- **Multi-threaded scanning**: Parallel processing for faster scans of large codebases
- **Context-aware**: Analyzes function arguments and AST context for better accuracy
- **Configurable rules**: RON-based rule system for different vulnerability types
- **Pattern matching**: Supports wildcards, regex patterns, and exact matching

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
- `<rules_file>`: RON file containing vulnerability detection rules

### Examples

```bash
# Auto-detection: scans all supported file types with appropriate rules
cargo run -- ./my_project

# Auto-detection with JSON output
cargo run -- ./my_project --output-format json

# Auto-detection with CSV output
cargo run -- ./my_project --output-format csv

# Auto-detection with verbose output
cargo run -- ./my_project --verbose

# Explicit mode: scan only Python files
cargo run -- ./my_project python rules/python/general.ron

# Explicit mode: scan with all Python rules in directory
cargo run -- ./my_project python rules/python

# Single-threaded mode for debugging
cargo run -- ./my_project --single-threaded

# Specify number of threads
cargo run -- ./my_project --threads 4
```

### Supported File Types

The auto-detection mode supports:
- **Python** (`.py`) - Uses `rules/python/` 
- **Java** (`.java`) - Uses `rules/java/`
- **JavaScript** (`.js`, `.mjs`) - Uses `rules/javascript/`
- **TypeScript JSX** (`.tsx`) - Uses `rules/tsx/`
- **HTML** (`.html`) - Uses `rules/html/`

## Rule Format

Rules are defined in RON format with the following structure:

```ron
{
    injection_sinks: [
        (
            pattern: "cursor.execute",
            finding_type: "sql_injection",
            severity: "high",
            confidence: "medium",
            conditions: [
                (
                    type: "not_literal",
                    argument_position: 0,
                ),
                (
                    type: "has_argument",
                    patterns: ["*SELECT*", "*INSERT*"],
                ),
            ],
            file_types: (
                extensions: [".py"],
                include_patterns: ["*models*", "*views*"],
                exclude_patterns: ["*test*"],
            ),
        ),
    ],
    crypto_rules: [
        (
            patterns: [
                "hashlib.md5",
                "hashlib.sha1"
            ],
            finding_type: "weak_crypto",
            severity: "high",
            confidence: "high",
        ),
    ],
}
```

### Rule Categories

- `injection_sinks`: SQL injection, command injection, etc.
- `crypto_rules`: Weak cryptographic functions
- `path_traversal`: Path traversal vulnerabilities
- `weak_random`: Weak random number generation
- `hardcoded_secrets`: Hardcoded credentials/secrets
- `malware_detection`: Malicious code patterns
- Custom categories can be added

### Pattern Types

1. **Exact match**: `"os.system"`
2. **Wildcard**: `"*.execute*"` (matches any string containing "execute")
3. **Regex**: `"regex:^subprocess\.(run|call)$"`
4. **Multiple patterns**: `patterns: ["pattern1", "pattern2"]`

### Rule Fields

- `pattern` or `patterns`: The pattern(s) to match
- `finding_type`: Type of vulnerability
- `severity`: Critical, High, Medium, Low
- `confidence`: High, Medium, Low
- `conditions`: Additional matching conditions
- `file_types`: File type restrictions
- `sanitizers`: Known safe functions

### Conditions

Rules can include conditions for more precise matching:

- `not_literal`: Check if argument is not a literal value
- `has_argument`: Check if function has specific arguments
- `has_sibling_pattern`: Check for related patterns in sibling nodes
- `argument_not_sanitized`: Check if input is not sanitized
- `in_context`: Context-aware checks (e.g., not in comments)

### File Type Targeting

Each rule can specify which file types it applies to:

```ron
file_types: (
    extensions: [".py", ".pyw"],
    include_patterns: ["*models*", "*views*"],
    exclude_patterns: ["*test*", "*migrations*"],
),
```

## Output Formats

The scanner provides three output formats:

### Text Output (Default)
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

### JSON Output
```json
[
  {
    "file": "./src/models.py",
    "line": 42,
    "function": "cursor.execute",
    "finding_type": "sql_injection",
    "severity": "high",
    "code": "cursor.execute('SELECT * FROM users WHERE id = ' + user_input)"
  }
]
```

### CSV Output
```csv
file,line,function,finding_type,code
./src/models.py,42,cursor.execute,sql_injection,"cursor.execute('SELECT * FROM users WHERE id = ' + user_input)"
```

## Contributing

To add support for new languages:

1. Add the appropriate tree-sitter language dependency to `Cargo.toml`
2. Update the `VulnerabilityScanner::new()` method to handle the new language
3. Update `detect_language_from_path()` method for the file extension
4. Create rule files for the new language in `rules/<language>/`

## License

This project is open source. Please check the license file for details. 

## Roadmap

- Multiple patterns ✅
- Run scan on all rules ✅
- Run scan on a directory of rules ✅
- Glob Support ✅
- Tree-sitter support ✅
- Enhanced rule conditions ✅
- Multiple output formats ✅
- Parallel processing ✅