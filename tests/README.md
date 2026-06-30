# Test Organization

This directory contains all the tests for the vulnerability scanner. The tests are organized into three categories:

## Directory Structure

- **unit/**: Tests for individual components
  - `injection_pattern_tests.rs`: Tests for injection pattern detection
  - `django_xss_prevention_tests.rs`: Tests for Django XSS prevention
  - `file_pattern_tests.rs`: Tests for file pattern matching
  - `directory_loading_tests.rs`: Tests for directory loading
  - `rule_deserialization_tests.rs`: Tests for rule deserialization
  - `pattern_matching_tests.rs`: Tests for pattern matching

- **integration/**: Tests for multiple components working together
  - `integration_tests.rs`: Tests for integrating rule parsing, scanning, and results

- **end_to_end/**: Tests for the entire system
  - `end_to_end_injection_tests.rs`: End-to-end tests for injection vulnerability detection

## Running Tests

To run all tests:
```bash
cargo test
```

To run a specific category of tests:
```bash
cargo test unit_tests
cargo test integration_tests
cargo test end_to_end_tests
```

To run a specific test:
```bash
cargo test pattern_matching
```

## Test Fixtures

Sample code fixtures live under `tests/test_files/`, organized by language:

- `tests/test_files/python/`: Python test files
- `tests/test_files/java/`: Java test files
- `tests/test_files/javascript/`: JavaScript/TypeScript test files

Rule files used by the scanner live in the top-level `rules/` directory.

## Test Scripts

Helper scripts (e.g. `run_comprehensive_tests.py`) live alongside the fixtures they
exercise, such as `tests/test_files/multi_file_taint_tests/`. 