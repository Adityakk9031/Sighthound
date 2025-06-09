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

Test fixtures (sample code and rule files) are located in the `test_fixtures/` directory at the project root.

- `test_fixtures/python/`: Python test files
- `test_fixtures/java/`: Java test files
- `test_fixtures/rules/`: Rule files for testing

## Test Scripts

Test scripts and utilities are located in the `test_scripts/` directory at the project root. 