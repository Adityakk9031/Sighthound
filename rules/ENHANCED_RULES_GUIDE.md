# Enhanced Rules Engine Guide

This document explains the enhanced rules engine that leverages tree-sitter's power to provide more accurate vulnerability detection with reduced false positives. The engine supports both single patterns and multiple patterns (Semgrep-style `pattern-either`) functionality.

## Overview

The enhanced rules engine builds upon the existing system by adding sophisticated tree-sitter based conditions and analysis capabilities. This allows for context-aware detection that understands code structure, data flow, and protective patterns.

## Rule Structure

### Basic Rule Format

Each rule follows this structure in RON format:

```ron
(
    // EITHER single pattern (backward compatible)
    pattern: Some("function_name"),
    
    // OR multiple patterns (new Semgrep-style pattern-either)
    patterns: Some([
        "pattern1",
        "pattern2", 
        "pattern3"
    ]),
    
    // Required fields
    finding_type: Some("vulnerability_type"),
    
    // Optional fields
    severity: Some("high"),           // critical, high, medium, low
    confidence: Some("high"),         // high, medium, low
    conditions: Some([...]),          // Enhanced conditions
    sanitizers: Some([...]),          // Known safe functions
    file_types: Some((               // File filtering
        extensions: [".py"],
        include_patterns: None,
        exclude_patterns: None,
    )),
)
```

### Pattern vs Patterns

**Important**: A rule MUST have either `pattern` OR `patterns`, but not both:

- **Single Pattern**: `pattern: Some("exact_function_name")`
- **Multiple Patterns**: `patterns: Some(["pattern1", "pattern2", "pattern3"])`

## Pattern Types and Syntax

### 1. Exact Matches
```ron
pattern: Some("os.system")          // Matches exactly "os.system"
```

### 2. Wildcard Patterns
```ron
pattern: Some("*.execute")          // Matches "cursor.execute", "conn.execute", etc.
pattern: Some("*clipboard*")        // Matches any function containing "clipboard"
```

### 3. Multiple Patterns (Semgrep-style pattern-either)
```ron
patterns: Some([
    "pyperclip.paste",
    "pyperclip.copy",
    "pandas.read_clipboard",
    "*.to_clipboard"
])
```

### 4. Regex Patterns
```ron
pattern: Some("regex:^(eval|exec)$")  // Matches eval or exec exactly
```

## Enhanced Condition Types

### `not_literal`
Ensures that arguments are not literal values (strings, numbers, etc.), which are typically safe.

```ron
(
    type: "not_literal",
    argument_position: Some(0),  // Check specific argument position (0-indexed)
)
```

**Example**: This prevents false positives from `cursor.execute("SELECT * FROM users")` (literal string).

### `not_in_protective_context`
Skips findings when code is in protective structures like try/catch blocks or input validation.

```ron
(
    type: "not_in_protective_context",
)
```

**Example**: Less likely to report vulnerabilities inside try/except blocks.

### `has_argument`
Checks if function arguments match specific patterns.

```ron
(
    type: "has_argument",
    pattern: Some("*user_input*"),           // Single pattern
    patterns: Some(["*request*", "*input*"]), // Multiple patterns
    argument_position: Some(0),              // Specific position (optional)
)
```

### `argument_not_sanitized`
Verifies that arguments don't contain known sanitization functions.

```ron
(
    type: "argument_not_sanitized",
    patterns: Some([
        "*escape*", "*quote*", "*sanitize*", "*clean*"
    ]),
)
```

### `has_ancestor`
Checks if the vulnerable call is within specific AST node types.

```ron
(
    type: "has_ancestor",
    ancestor_types: Some(["assignment", "function_definition"]),
)
```

### `has_sibling_pattern`
Checks for patterns in sibling nodes (useful for detecting related validation code).

```ron
(
    type: "has_sibling_pattern",
    patterns: Some(["*validation*", "*check*"]),
)
```

### `has_parent`
Checks if the node has a specific parent type.

```ron
(
    type: "has_parent",
    parent_type: Some("assignment"),
)
```

### `in_context`
Checks contextual conditions with exclusions.

```ron
(
    type: "in_context",
    not_in: Some(["comment", "string"]),  // Don't match in comments or strings
)
```

## Key Improvements

### 1. Multiple Patterns Support (New!)

Instead of creating separate rules for related patterns, you can now consolidate them:

**Before (Multiple Rules)**:
```ron
(pattern: Some("pyperclip.paste"), finding_type: Some("clipboard_access")),
(pattern: Some("pyperclip.copy"), finding_type: Some("clipboard_access")),
(pattern: Some("pandas.read_clipboard"), finding_type: Some("clipboard_access")),
```

**After (Single Rule with Multiple Patterns)**:
```ron
(
    patterns: Some([
        "pyperclip.paste",
        "pyperclip.copy",
        "pandas.read_clipboard",
        "*.to_clipboard"
    ]),
    finding_type: Some("clipboard_access"),
)
```

### 2. Enhanced Rule Fields

#### Confidence and Severity
Rules include confidence and severity ratings to help prioritize findings.

```ron
(
    severity: Some("high"),      // critical, high, medium, low
    confidence: Some("medium"),  // high, medium, low
)
```

#### Sanitizers
Specify known sanitization functions that should suppress findings.

```ron
sanitizers: Some([
    "html.escape", "urllib.parse.quote", "*sanitize*"
]),
```

## Practical Examples

### Example 1: Clipboard Access Detection
```ron
(
    patterns: Some([
        "pyperclip.paste",
        "pyperclip.copy",
        "pandas.read_clipboard", 
        "*.to_clipboard",
        "tkinter.clipboard",
        "win32clipboard"
    ]),
    finding_type: Some("clipboard_access"),
    severity: Some("medium"),
    confidence: Some("high"),
    conditions: None,
    file_types: Some((
        extensions: [".py"],
        include_patterns: None,
        exclude_patterns: None,
    )),
)
```

### Example 2: SQL Injection with Enhanced Conditions
```ron
(
    patterns: Some([
        "*.execute",
        "*.executemany", 
        "cursor.execute",
        "connection.execute"
    ]),
    finding_type: Some("sql_injection"),
    severity: Some("high"),
    confidence: Some("high"),
    conditions: Some([
        // Only dynamic content
        (
            type: "not_literal",
            argument_position: Some(0),
        ),
        // Not in protective context
        (
            type: "not_in_protective_context",
        ),
        // Has injection patterns
        (
            type: "has_argument",
            patterns: Some(["*+*", "*%*", "*format*", "*f\"*"]),
        ),
        // Not sanitized
        (
            type: "argument_not_sanitized",
            patterns: Some(["*escape*", "*quote*", "*sanitize*"]),
        ),
    ]),
    sanitizers: Some([
        "*.escape", "*.quote", "*sanitize*", "psycopg2.sql.*"
    ]),
    file_types: Some((
        extensions: [".py"],
        include_patterns: None,
        exclude_patterns: None,
    )),
)
```

### Example 3: Suspicious Network Communication
```ron
(
    patterns: Some([
        "*.tk*",      // Free TLD domains
        "*.ml*",
        "*.ga*", 
        "*.cf*",
        "bit.ly",     // URL shorteners
        "t.co",
        "tinyurl"
    ]),
    finding_type: Some("suspicious_network"),
    severity: Some("medium"),
    confidence: Some("medium"),
    conditions: Some([
        (
            type: "has_argument",
            patterns: Some(["*http*", "*url*", "*request*"]),
        )
    ]),
    file_types: Some((
        extensions: [".py"],
        include_patterns: None,
        exclude_patterns: None,
    )),
)
```

### Example 4: Path Traversal with Context Analysis
```ron
(
    pattern: Some("open"),
    finding_type: Some("path_traversal"),
    severity: Some("medium"),
    confidence: Some("medium"),
    conditions: Some([
        // Look for traversal patterns
        (
            type: "has_argument",
            patterns: Some(["*../*", "*user*", "*request*"]),
        ),
        // Not using safe path functions
        (
            type: "argument_not_sanitized",
            patterns: Some([
                "*os.path.abspath*", "*pathlib.Path*", "*secure_filename*"
            ]),
        ),
        // Not in validation context
        (
            type: "not_in_protective_context",
        ),
    ]),
    sanitizers: Some([
        "os.path.abspath", "pathlib.Path", "werkzeug.utils.secure_filename"
    ]),
    file_types: Some((
        extensions: [".py"],
        include_patterns: None,
        exclude_patterns: None,
    )),
)
```

## Reduced False Positives

### Literal Detection
The engine automatically skips vulnerabilities in literal values:

```python
# This won't trigger SQL injection (literal string)
cursor.execute("SELECT * FROM users WHERE id = 1")

# This will trigger (dynamic content)
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### Context Awareness
Code in protective contexts is treated differently:

```python
# Less likely to report (in try/except block)
try:
    cursor.execute(query)
except Exception:
    handle_error()

# More likely to report (no protection)
cursor.execute(query)
```

### Sanitization Detection
The engine recognizes sanitization patterns:

```python
# Won't trigger (sanitized)
safe_query = html.escape(user_input)
cursor.execute(f"SELECT * FROM users WHERE name = '{safe_query}'")

# Will trigger (not sanitized)
cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
```

## File Type Filtering

Rules can be restricted to specific file types:

```ron
file_types: Some((
    extensions: [".py", ".pyw"],           // Python files only
    include_patterns: Some(["*config*"]), // Files with "config" in name
    exclude_patterns: Some(["*test*"]),   // Exclude test files
)),
```

## Rule Categories

Rules are organized into categories within the rules file:

- `injection_sinks`: SQL injection, command injection, etc.
- `crypto_rules`: Cryptographic vulnerabilities
- `path_traversal`: Directory traversal vulnerabilities  
- `weak_random`: Weak randomness issues
- `hardcoded_secrets`: Hardcoded passwords, keys, etc.
- `malware_detection`: Malicious behavior patterns
- Custom categories can be added under `other`

## Writing Effective Rules

### 1. Choose Between Single and Multiple Patterns

**Use Single Pattern When**:
- Detecting a specific function call
- The pattern is unique and doesn't relate to others

**Use Multiple Patterns When**:
- Grouping related functionality (e.g., all clipboard access methods)
- Consolidating similar vulnerability patterns
- Reducing rule file size and maintenance

### 2. Pattern Design Best Practices

```ron
// Good: Specific and targeted
patterns: Some([
    "eval", 
    "exec",
    "compile"
])

// Avoid: Too broad, may cause false positives
pattern: Some("*")

// Good: Uses wildcards appropriately
patterns: Some([
    "*.execute",
    "*cursor.execute*"
])
```

### 3. Condition Layering

Layer conditions from most to least restrictive:

```ron
conditions: Some([
    (type: "not_literal", argument_position: Some(0)),      // Most restrictive
    (type: "not_in_protective_context"),                    // Medium restrictive  
    (type: "has_argument", patterns: Some(["*user*"])),     // Least restrictive
]),
```

### 4. Confidence and Severity Guidelines

**High Confidence**:
- Well-tested patterns with low false positive rates
- Clear vulnerability indicators

**Medium Confidence**: 
- Patterns that may have some false positives
- Context-dependent vulnerabilities

**Low Confidence**:
- Experimental or broad patterns
- Patterns requiring manual review

## Migration from Basic Rules

Existing rules continue to work unchanged. To enhance them:

1. **Add confidence levels** to help prioritize findings
2. **Add sanitizers** to reduce false positives from protected code
3. **Use enhanced conditions** for more precise matching
4. **Consolidate related patterns** using the new multiple patterns feature
5. **Specify argument positions** for targeted analysis

## Performance Considerations

The enhanced engine is designed for performance:

- **Selective Analysis**: Only analyzes relevant code paths
- **Depth Limits**: Prevents deep tree traversals  
- **Efficient Caching**: Reuses compiled patterns and queries
- **Smart Filtering**: Applies confidence-based filtering
- **Pattern Consolidation**: Multiple patterns reduce rule processing overhead

## Rule Validation

The engine validates rules at load time:

- Rules must have either `pattern` OR `patterns` (not both)
- Pattern arrays cannot be empty
- Individual patterns cannot be empty strings
- Conditions must have valid types
- File extensions must start with "."

## Best Practices for LLM Rule Generation

1. **Start with high confidence rules** and gradually add medium/low confidence ones
2. **Use specific argument positions** when possible to reduce analysis overhead
3. **Define comprehensive sanitizer lists** for your technology stack
4. **Test rules against known codebases** to validate false positive rates
5. **Use protective context checks** judiciously to avoid missing real vulnerabilities
6. **Consolidate related patterns** into single rules using the `patterns` array
7. **Include clear comments** explaining the vulnerability being detected
8. **Set appropriate severity levels** based on potential impact
9. **Use file type filtering** to scope rules appropriately
10. **Layer conditions** from most to least restrictive for optimal performance

## Example Rule Categories for Common Vulnerabilities

### Web Application Security
- SQL Injection: `*.execute*`, `*.query*` with dynamic content
- XSS: Template rendering without escaping
- CSRF: Form handling without token validation

### System Security  
- Command Injection: `os.system`, `subprocess.*` with user input
- Path Traversal: File operations with `../` patterns
- Privilege Escalation: Unsafe file permissions, sudo usage

### Cryptography
- Weak Algorithms: MD5, SHA1, DES usage
- Hardcoded Secrets: Embedded passwords, API keys
- Insecure Random: `random.random()` for security purposes

### Network Security
- Unencrypted Communication: HTTP instead of HTTPS
- Certificate Validation: Disabled SSL verification
- Suspicious Domains: Known malicious TLDs, URL shorteners

This comprehensive guide provides the foundation for writing effective vulnerability detection rules using the enhanced rules engine with both single and multiple pattern support. 