# Test Suite Documentation

This directory contains the unified test suite for the Greppy vulnerability scanner.

## Directory Structure

```
test_data/
├── README.md                    # This file
├── test_clean_syntax.ron        # Test rule file for syntax validation
├── python/                      # Python test files for scanning
│   ├── README.md               # Python test documentation
│   ├── django/                 # Django-specific vulnerability tests
│   │   └── django_views.py     # Django XSS, SQL injection, deserialization tests
│   ├── general/                # General Python vulnerability tests
│   │   ├── simple_eval.py      # Basic eval vulnerability test
│   │   ├── another_test.py     # Additional test patterns
│   │   ├── vulnerable_test.py  # Complex vulnerability patterns
│   │   ├── test_filtering.py   # Pre-filtering functionality test
│   │   ├── migration_example.py # Migration file filtering test
│   │   ├── test_1.py           # Sample numbered test file
│   │   ├── test_10.py         # Sample numbered test file
│   │   └── test_20.py         # Sample numbered test file
│   └── malicious/              # Malicious pattern detection tests
│       ├── test_multiple_patterns.py     # Multiple pattern rule tests
│       └── test_multiple_patterns_alt.py # Alternative pattern tests
└── run_tests.sh                # Test runner script
```

## Test Categories

### Django Tests (`python/django/`)
- **django_views.py**: Contains Django-specific vulnerabilities including:
  - XSS via HttpResponse with user input
  - SQL injection via cursor.execute with f-strings
  - Unsafe deserialization via pickle.loads
  - Code injection via eval

### General Python Tests (`python/general/`)
- **simple_eval.py**: Basic eval vulnerability detection
- **vulnerable_test.py**: Complex vulnerability patterns with multiple injection types
- **test_filtering.py**: Tests pre-filtering functionality
- **migration_example.py**: Tests migration file filtering
- **test_*.py**: Sample test files for bulk scanning tests

### Malicious Pattern Tests (`python/malicious/`)
- **test_multiple_patterns.py**: Tests multiple pattern rules including:
  - Clipboard access patterns (pyperclip, pandas, tkinter, win32)
  - Keyboard hook patterns
  - Suspicious domain patterns
  - URL shortener patterns

## Running Tests

### Individual Test Categories
```bash
# Test Django rules
./target/release/find_vulns test_data/python/django python rules/python/django/

# Test general Python rules  
./target/release/find_vulns test_data/python/general python rules/python/python/general.ron

# Test malicious pattern detection
./target/release/find_vulns test_data/python/malicious python rules/python/malicious/

# Test all Python files
./target/release/find_vulns test_data/python python rules/python/python/general.ron
```

### Performance Testing
```bash
# Test parser pooling performance
./target/release/find_vulns test_data/python python rules/python/python/general.ron --threads 8

# Test pre-filtering functionality
./target/release/find_vulns test_data/python python rules/python/django/ --threads 1
```

### Rust Unit Tests
```bash
# Run all Rust unit and integration tests
cargo test

# Run specific test categories
cargo test pattern_matching
cargo test rule_deserialization
cargo test integration
```

## Expected Results

### Django Rules (test_data/python/django/)
- **django_views.py**: Should detect 4 vulnerabilities:
  - Django XSS on line 8 (HttpResponse)
  - Django SQL injection on line 16 (cursor.execute)
  - Django unsafe deserialization on line 22 (pickle.loads)
  - Django code injection on line 27 (eval)

### General Rules (test_data/python/general/)
- **simple_eval.py**: Should detect 1 eval vulnerability
- **vulnerable_test.py**: Should detect multiple SQL injection and other patterns
- **migration_example.py**: Should be filtered out in general mode

### Malicious Patterns (test_data/python/malicious/)
- **test_multiple_patterns.py**: Should detect:
  - Multiple clipboard access patterns
  - Keyboard hook patterns
  - Suspicious domain access
  - URL shortener usage

## Test Maintenance

When adding new test cases:
1. Place them in the appropriate category directory
2. Update this README with expected results
3. Ensure test files contain realistic vulnerability patterns
4. Add corresponding rules if testing new vulnerability types

## Integration with CI/CD

This test suite is designed to be run in continuous integration:
- Rust unit tests validate core functionality
- Python test files validate end-to-end scanning
- Performance tests ensure optimization effectiveness
- Rule syntax tests prevent deployment of broken rules 