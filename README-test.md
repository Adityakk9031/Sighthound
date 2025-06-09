# Test Organization

This project has a well-organized test structure to make it easier to maintain and run tests. The test organization follows a layered approach:

## Directory Structure

1. **tests/**: Contains all test code
   - **unit/**: Unit tests for individual components
   - **integration/**: Tests for multiple components working together
   - **end_to_end/**: Tests for the entire system

2. **test_fixtures/**: Contains all test data and fixtures
   - **python/**: Python test files for Python-specific vulnerabilities
   - **java/**: Java test files for Java-specific vulnerabilities
   - **javascript/**: JavaScript test files for JavaScript-specific vulnerabilities
   - **rules/**: Test rule files in RON format

3. **test_scripts/**: Contains scripts and utilities for running tests
   - `run_tests.sh`: Main test runner script
   - `test_java_rules.sh`: Script for testing Java rules

## Running Tests

### With Cargo

```bash
# Run all tests
cargo test

# Run specific test categories
cargo test unit_tests
cargo test integration_tests
cargo test end_to_end_tests

# Run specific tests
cargo test python_injection
```

### With Test Scripts

```bash
# Run all tests with the test runner script
./test_scripts/run_tests.sh

# Run Java-specific tests
./test_scripts/test_java_rules.sh
```

## Test Organization Benefits

This test organization provides several benefits:

1. **Clear Separation of Concerns**: Tests are organized by scope and purpose
2. **Easy to Find and Run**: Tests are grouped logically, making them easy to locate and run
3. **Maintainable**: Each test category has its own main.rs file
4. **Efficient**: Test fixtures are centralized and reused across test categories

## Adding New Tests

When adding new tests:

1. Determine the appropriate category (unit, integration, end-to-end)
2. Add the test to the appropriate file in that category
3. Add any required test fixtures to the `test_fixtures` directory
4. Update the relevant README files if necessary

See the README files in each directory for more specific information:
- [tests/README.md](tests/README.md)
- [test_fixtures/README.md](test_fixtures/README.md)
- [test_scripts/README.md](test_scripts/README.md) 