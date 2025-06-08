# Enhanced Rules Engine Guide

This document explains how to write effective vulnerability detection rules that minimize false positives while maintaining high accuracy. The engine uses tree-sitter for syntax understanding, but the focus is on **smart rule design** and **contextual analysis**.

## Overview

The rules engine detects security vulnerabilities by matching patterns in code and applying conditions to filter out false positives. The key to effective rules is **precision over breadth** - targeting specific dangerous patterns while excluding common legitimate uses.

### Rule Syntax: Clean and Intuitive

🎉 **NEW**: We've implemented clean syntax that removes the need for `Some()` wrappers while maintaining full optionality support.

**✅ Clean Syntax (Current)**:
```ron
{
    injection_sinks: [
        (
            pattern: "cursor.execute",
            finding_type: "sql_injection",
            severity: "high",
            confidence: "medium",
        ),
    ],
}
```

**📜 Legacy Syntax (Still Supported)**:
```ron
{
    injection_sinks: Some([
        (
            pattern: "cursor.execute",
            finding_type: Some("sql_injection"),
            severity: Some("high"),
            confidence: Some("medium"),
        ),
    ]),
}
```

### Common False Positive Patterns (Avoid These!)

Based on real-world analysis, these patterns generate many false positives:

❌ **Overly Broad Patterns**:
- `os.path.join` → flagged as "credential_theft" (just normal path construction)
- `os.path.exists` → flagged as "anti_analysis" (just checking file existence)  
- `socket.socket` → flagged as "backdoor" (legitimate networking)
- `shutil.copy` → flagged as "persistence" (normal file operations)
- `subprocess.Popen` → flagged as "reverse_shell" (legitimate process execution)

✅ **Better Approaches**: Add **context and specificity** to distinguish malicious from legitimate usage.

## Rule Structure

### Complete File Structure

Rules are organized in RON format with named categories:

```ron
{
    // Named categories contain arrays of rules
    injection_sinks: [
        (
            pattern: "cursor.execute",
            finding_type: "sql_injection",
            severity: "high",
            confidence: "high",
            conditions: [
                (
                    type: "not_literal",
                    argument_position: 0,
                ),
            ],
        ),
    ],
    
    malware_detection: [
        (
            patterns: [
                "hashlib.sha256",
                "hashlib.sha1"
            ],
            finding_type: "cryptomining",
            // Add conditions to avoid false positives
            conditions: [
                (type: "has_argument", patterns: ["*nonce*", "*mining*", "*hashrate*"]),
            ],
        ),
    ],
}
```

### Individual Rule Format

Each rule is a tuple with these fields:

```ron
(
    // EITHER single pattern
    pattern: "function_name",
    
    // OR multiple patterns (consolidate related functionality)
    patterns: ["pattern1", "pattern2"],
    
    // Required fields
    finding_type: "vulnerability_type",
    
    // Optional fields for accuracy
    severity: "high",           // critical, high, medium, low
    confidence: "medium",       // high, medium, low - be realistic!
    conditions: [...],          // Key to reducing false positives
    sanitizers: [...],          // Known safe functions
    file_types: (               // Restrict to relevant files
        extensions: [".py"],
        include_patterns: ["*models*", "*views*"],
        exclude_patterns: ["*test*"], // Exclude test files
    ),
)
```

## Writing Accurate Rules: Key Principles

### 1. Start Specific, Not Broad

❌ **Too Broad** (causes false positives):
```ron
(
    pattern: "os.system",  // Will flag ALL os.system calls
    finding_type: "command_injection",
)
```

✅ **More Specific** (reduces false positives):
```ron
(
    pattern: "os.system",
    finding_type: "command_injection",
    conditions: [
        // Only flag dynamic content, not hardcoded commands
        (type: "not_literal", argument_position: 0),
        // Look for user input patterns
        (type: "has_argument", patterns: ["*user*", "*input*", "*request*"]),
    ],
)
```

### 2. Use Contextual Conditions

The `conditions` field is your most powerful tool for accuracy:

```ron
conditions: [
    // Exclude hardcoded/literal values (major false positive reducer)
    (type: "not_literal", argument_position: 0),
    
    // Exclude comments and strings  
    (type: "in_context", not_in: ["comment", "string_literal"]),
    
    // Look for suspicious argument patterns
    (type: "has_argument", patterns: ["*user*", "*input*", "*request*"]),
    
    // Exclude known safe functions
    (type: "argument_not_sanitized", patterns: ["*escape*", "*sanitize*"]),
    
    // Less likely to report in protected contexts
    (type: "not_in_protective_context"),
],
```

### 3. Set Realistic Confidence Levels

Many false positives come from overconfident rules:

```ron
// ❌ Too confident for a broad pattern
(
    pattern: "subprocess.Popen",
    confidence: "high",  // This will cause false positives
)

// ✅ Realistic confidence with conditions
(
    pattern: "subprocess.Popen", 
    confidence: "medium",  // More honest assessment
    conditions: [
        (type: "has_argument", patterns: ["*shell=True*", "*cmd*", "*command*"]),
        (type: "not_literal", argument_position: 0),
    ],
)
```

### 4. Exclude Test Files and Safe Contexts

```ron
file_types: (
    extensions: [".py"],
    exclude_patterns: [
        "*test*",           // Exclude test files
        "*example*",        // Exclude example code
        "*demo*",           // Exclude demos
    ],
),
```

## Pattern Types and Best Practices

### 1. Exact Function Matches
```ron
pattern: "eval"  // Matches exactly "eval"
```

### 2. Wildcard Patterns (Use Carefully)
```ron
pattern: "*.execute"      // Good: specific enough
pattern: "*"              // Bad: too broad
pattern: "*clipboard*"    // OK: targets specific functionality
```

### 3. Multiple Related Patterns
```ron
patterns: [
    "pyperclip.paste",
    "pyperclip.copy", 
    "pandas.read_clipboard"
]
```

### 4. Regex Patterns (Advanced)
```ron
pattern: "regex:^(eval|exec)$"  // Exact matches only
```

## Essential Condition Types

### `not_literal` - Avoid Hardcoded False Positives
**Most important condition for reducing false positives!**

```ron
(type: "not_literal", argument_position: 0)
```

**Prevents false positives like**:
```python
cursor.execute("SELECT * FROM users")  # ← Literal string (safe)
cursor.execute(user_query)             # ← Variable (potentially unsafe)
```

### `has_argument` - Look for Suspicious Patterns
```ron
(type: "has_argument", patterns: ["*user*", "*input*", "*request*"])
```

**Targets dangerous patterns**:
```python
os.system(user_input)        # ← Has "user" pattern (suspicious)
os.system("ls -la")          # ← No user pattern (less suspicious)
```

### `argument_not_sanitized` - Check for Safety Measures
```ron
(type: "argument_not_sanitized", patterns: ["*escape*", "*sanitize*", "*quote*"])
```

**Excludes sanitized input**:
```python
safe_cmd = shlex.quote(user_input)  # Sanitized
os.system(safe_cmd)                 # ← Won't trigger (sanitized)

os.system(user_input)               # ← Will trigger (not sanitized)
```

### `in_context` - Exclude Comments and Strings
```ron
(type: "in_context", not_in: ["comment", "string_literal"])
```

**Prevents matches in**:
```python
# eval("malicious code")  ← IGNORED (in comment)
"eval(dangerous)"         # ← IGNORED (in string)
eval(user_input)          # ← DETECTED (actual code)
```

### `not_in_protective_context` - Context Awareness
```ron
(type: "not_in_protective_context")
```

**Less likely to report in**:
```python
try:
    risky_operation()  # ← Less suspicious (protected context)
except:
    handle_error()

risky_operation()      # ← More suspicious (no protection)
```

## Real-World Examples: Fixing Common False Positives

### Example 1: Path Operations (Fix for `os.path.join` false positives)

❌ **Causes False Positives**:
```ron
(
    pattern: "os.path.join",
    finding_type: "credential_theft",  // Too generic!
)
```

✅ **Better - Target Suspicious Paths**:
```ron
(
    pattern: "os.path.join",
    finding_type: "credential_theft",
    confidence: "medium",  // More realistic
    conditions: [
        // Look for credential-related paths
        (type: "has_argument", patterns: [
            "*password*", "*secret*", "*key*", "*token*", 
            "*credential*", "*.ssh*", "*id_rsa*"
        ]),
        // Exclude normal path construction
        (type: "not_literal", argument_position: 1),
    ],
)
```

### Example 2: File Existence Checks (Fix for `os.path.exists` false positives)

❌ **Causes False Positives**:
```ron
(
    pattern: "os.path.exists", 
    finding_type: "anti_analysis",  // Too broad!
)
```

✅ **Better - Target Analysis Evasion**:
```ron
(
    pattern: "os.path.exists",
    finding_type: "anti_analysis",
    confidence: "low",  // Honest about confidence
    conditions: [
        // Look for analysis tool paths
        (type: "has_argument", patterns: [
            "*debugger*", "*wireshark*", "*procmon*", "*olly*",
            "*ida*", "*x64dbg*", "*vmware*", "*virtualbox*"
        ]),
    ],
)
```

### Example 3: Network Operations (Fix for `socket.socket` false positives)

❌ **Causes False Positives**:
```ron
(
    pattern: "socket.socket",
    finding_type: "backdoor",  // Flags legitimate networking!
)
```

✅ **Better - Target Suspicious Network Behavior**:
```ron
(
    patterns: [
        "socket.socket",
        "socket.create_connection"
    ],
    finding_type: "suspicious_network",
    confidence: "low",  // Be realistic
    conditions: [
        // Look for backdoor patterns
        (type: "has_argument", patterns: [
            "*bind*", "*listen*", "*accept*",
            "*shell*", "*cmd*", "*reverse*"
        ]),
        // Exclude normal client connections
        (type: "argument_not_sanitized", patterns: [
            "*http*", "*https*", "*api*", "*service*"
        ]),
    ],
)
```

### Example 4: SQL Injection with High Accuracy

✅ **Well-Designed Rule**:
```ron
(
    patterns: [
        "*.execute",
        "*.executemany", 
        "cursor.execute"
    ],
    finding_type: "sql_injection",
    severity: "high",
    confidence: "high",
    conditions: [
        // Must be dynamic content (not hardcoded queries)
        (type: "not_literal", argument_position: 0),
        
        // Look for string formatting/concatenation
        (type: "has_argument", patterns: [
            "*+*", "*%*", "*format*", "*f\"*", "*.format(*"
        ]),
        
        // Not sanitized with proper methods
        (type: "argument_not_sanitized", patterns: [
            "*escape*", "*quote*", "psycopg2.sql.*", "*parameterized*"
        ]),
        
        // Exclude comments and test code
        (type: "in_context", not_in: ["comment", "string_literal"]),
    ],
    sanitizers: [
        "psycopg2.sql.SQL", "*.escape", "*.quote"
    ],
    file_types: (
        extensions: [".py"],
        exclude_patterns: ["*test*", "*example*"],
    ),
)
```

## Advanced Rule Techniques

### 1. Layered Conditions (Order Matters)
Place most restrictive conditions first for performance:

```ron
conditions: [
    (type: "not_literal", argument_position: 0),      // Most restrictive
    (type: "in_context", not_in: ["comment"]),        // Medium
    (type: "has_argument", patterns: ["*user*"]),     // Least restrictive
],
```

### 2. Multiple Patterns for Related Functionality
```ron
patterns: [
    "base64.b64decode",
    "base64.standard_b64decode", 
    "base64.urlsafe_b64decode"
],
finding_type: "code_obfuscation",
conditions: [
    // Only flag if combined with execution
    (type: "has_sibling_pattern", patterns: ["exec", "eval"]),
],
```

### 3. File Type Scoping
```ron
file_types: (
    extensions: [".py", ".pyw"],
    include_patterns: ["*config*", "*settings*"],  // Focus on config files
    exclude_patterns: ["*test*", "*example*", "*demo*"],
),
```

## Confidence Level Guidelines

### High Confidence (95%+ accuracy expected)
- Specific patterns with multiple validating conditions
- Well-tested against known codebases
- Minimal false positive rate

```ron
confidence: "high",
conditions: [
    (type: "not_literal", argument_position: 0),
    (type: "has_argument", patterns: ["*injection_pattern*"]),
    (type: "argument_not_sanitized", patterns: ["*escape*"]),
],
```

### Medium Confidence (80-95% accuracy)
- Broader patterns with some contextual filtering
- May require manual review of some findings

```ron
confidence: "medium",
conditions: [
    (type: "not_literal", argument_position: 0),
    (type: "has_argument", patterns: ["*user*", "*input*"]),
],
```

### Low Confidence (60-80% accuracy)
- Experimental or broad patterns
- Useful for discovery but expect false positives

```ron
confidence: "low",
conditions: [
    (type: "has_argument", patterns: ["*suspicious*"]),
],
```

## Rule Categories and Organization

### Injection Vulnerabilities
- `sql_injection`: Database injection attacks
- `command_injection`: OS command injection
- `code_injection`: Dynamic code execution

### Cryptographic Issues  
- `weak_crypto`: Weak algorithms (MD5, SHA1, DES)
- `hardcoded_secrets`: Embedded passwords/keys
- `insecure_random`: Weak randomness for security

### Malware Indicators
- `backdoor`: Remote access capabilities
- `data_exfiltration`: Unauthorized data transmission
- `persistence`: Installation/persistence mechanisms
- `anti_analysis`: Analysis evasion techniques

### Path and File Operations
- `path_traversal`: Directory traversal attempts
- `sensitive_files`: Access to system files
- `file_manipulation`: Suspicious file operations

## Clean Syntax Examples

### Simple Rule
```ron
{
    injection_sinks: [
        (
            pattern: "eval",
            finding_type: "code_injection",
            severity: "critical",
        ),
    ],
}
```

### Complex Rule with All Features
```ron
{
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
            conditions: [
                (type: "not_literal", argument_position: 0),
                (type: "has_argument", patterns: ["*user*", "*request*", "*input*"]),
                (type: "argument_not_sanitized", patterns: ["*safe*", "*verify*"]),
            ],
            sanitizers: [
                "safe_pickle.loads",
                "verify_pickle"
            ],
            file_types: (
                extensions: [".py"],
                include_patterns: ["*views*", "*controllers*", "*handlers*"],
                exclude_patterns: ["*test*", "*example*"],
            ),
        ),
    ],
}
```

## Migration from Legacy Syntax

### Quick Migration Guide

**Legacy → Clean Syntax**:
1. Remove `Some([...])` → `[...]` for arrays
2. Remove `Some("value")` → `"value"` for strings  
3. Remove `Some((struct))` → `(struct)` for structs
4. Remove `None` fields entirely (they're optional)
5. Remove `Some(number)` → `number` for numeric values

**Example Migration**:
```ron
// Legacy (still works)
(
    pattern: "eval",
    finding_type: Some("code_injection"),
    severity: Some("high"),
    conditions: Some([
        (type: "not_literal", argument_position: Some(0)),
    ]),
    file_types: Some((
        extensions: Some([".py"]),
        exclude_patterns: Some(["*test*"]),
    )),
)

// Clean syntax (preferred)
(
    pattern: "eval",
    finding_type: "code_injection",
    severity: "high",
    conditions: [
        (type: "not_literal", argument_position: 0),
    ],
    file_types: (
        extensions: [".py"],
        exclude_patterns: ["*test*"],
    ),
)
```

## Best Practices for LLM Rule Generation

### 1. Always Start Conservative
- Begin with high specificity, low false positive rules
- Gradually broaden if needed, but maintain accuracy
- Prefer `medium` or `low` confidence over overconfident `high`

### 2. Use Real-World Context
- Consider legitimate uses of functions before flagging them
- Add conditions that exclude normal usage patterns
- Test against real codebases to validate accuracy

### 3. Layer Multiple Conditions
- Don't rely on pattern matching alone
- Combine multiple conditions for precision
- Use `not_literal` for almost all dynamic content rules

### 4. Focus on Intent, Not Just Function Calls
- Look for suspicious argument patterns
- Consider the context of function usage
- Exclude sanitized or protected contexts

### 5. Document Your Reasoning
```ron
// Rule for detecting SQL injection in database queries
// Targets dynamic query construction without proper sanitization
// Excludes literal queries and properly sanitized inputs
(
    patterns: ["*.execute", "*.query"],
    finding_type: "sql_injection",
    // ... conditions
)
```

### 6. Regular Testing and Refinement
- Monitor false positive rates
- Adjust conditions based on real-world feedback
- Update patterns as new libraries/frameworks emerge

## Common Pitfalls to Avoid

1. **Over-broad patterns** without sufficient conditions
2. **Overconfident severity ratings** for experimental rules
3. **Ignoring legitimate use cases** of flagged functions
4. **Not excluding test files** and example code
5. **Missing `not_literal` conditions** for dynamic content rules
6. **Too many low-value detections** that obscure real threats

## Performance Considerations

- **Specific patterns** reduce initial candidate matches
- **Layered conditions** allow early exit from expensive checks
- **File type filtering** prevents unnecessary analysis
- **Cached results** improve repeated analysis performance

The engine automatically optimizes rule execution, but well-designed rules with appropriate specificity will always perform better than overly broad patterns.

## Rule Validation

Rules are validated at load time:
- Must have either `pattern` OR `patterns` (not both)
- Patterns cannot be empty
- Condition types must be valid
- File extensions must start with "."
- Confidence levels must be valid

This guide provides the foundation for writing effective, accurate vulnerability detection rules that minimize false positives while maintaining security coverage. Focus on precision, context, and realistic confidence assessments for the best results. 