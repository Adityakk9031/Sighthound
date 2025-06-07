# Enhanced Rules Engine Guide

This document explains the enhanced rules engine that leverages tree-sitter's power to provide more accurate vulnerability detection with reduced false positives.

## Overview

The enhanced rules engine builds upon the existing system by adding sophisticated tree-sitter based conditions and analysis capabilities. This allows for context-aware detection that understands code structure, data flow, and protective patterns.

## Key Improvements

### 1. Enhanced Condition Types

#### `not_literal`
Ensures that arguments are not literal values (strings, numbers, etc.), which are typically safe.

```ron
(
    type: "not_literal",
    argument_position: Some(0),  // Check specific argument position
)
```

#### `not_in_protective_context`
Skips findings when code is in protective structures like try/catch blocks or input validation.

```ron
(
    type: "not_in_protective_context",
)
```

#### `has_ancestor`
Checks if the vulnerable call is within specific AST node types (e.g., inside assignments, functions).

```ron
(
    type: "has_ancestor",
    ancestor_types: Some(["assignment", "function_definition"]),
)
```

#### `argument_not_sanitized`
Verifies that arguments don't contain known sanitization functions.

```ron
(
    type: "argument_not_sanitized",
    patterns: Some([
        "*escape*", "*quote*", "*sanitize*", "*clean*"
    ]),
)
```

#### `has_sibling_pattern`
Checks for patterns in sibling nodes (useful for detecting related validation code).

```ron
(
    type: "has_sibling_pattern",
    patterns: Some(["*validation*", "*check*"]),
)
```

### 2. Enhanced Rule Fields

#### Confidence and Severity
Rules now include confidence and severity ratings to help prioritize findings.

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

### 3. Advanced Pattern Matching

#### Multiple Patterns
Support for multiple patterns in a single condition.

```ron
(
    type: "has_argument",
    patterns: Some(["*../*", "*..\\*", "*user*", "*request*"]),
)
```

#### Position-Specific Checks
Check specific argument positions rather than all arguments.

```ron
(
    type: "not_literal",
    argument_position: Some(0),  // First argument only
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

## Example Enhanced Rules

### SQL Injection with Reduced False Positives

```ron
(
    pattern: "*.execute",
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
            pattern: Some("*+*|*%*|*format*|*f\"*"),
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
)
```

### Path Traversal with Context Analysis

```ron
(
    pattern: "open",
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
)
```

## Migration from Basic Rules

Existing rules continue to work unchanged. To enhance them:

1. **Add confidence levels** to help prioritize findings
2. **Add sanitizers** to reduce false positives from protected code
3. **Use enhanced conditions** for more precise matching
4. **Specify argument positions** for targeted analysis

## Performance Considerations

The enhanced engine is designed for performance:

- **Selective Analysis**: Only analyzes relevant code paths
- **Depth Limits**: Prevents deep tree traversals
- **Efficient Caching**: Reuses compiled patterns and queries
- **Smart Filtering**: Applies confidence-based filtering

## Best Practices

1. **Start with high confidence rules** and gradually add medium/low confidence ones
2. **Use specific argument positions** when possible to reduce analysis overhead
3. **Define comprehensive sanitizer lists** for your technology stack
4. **Test rules against known codebases** to validate false positive rates
5. **Use protective context checks** judiciously to avoid missing real vulnerabilities

## Future Enhancements

Planned improvements include:

- **Data flow tracking** across function boundaries
- **Taint analysis** for more sophisticated vulnerability detection
- **Machine learning integration** for confidence scoring
- **Custom tree-sitter queries** for advanced pattern matching 