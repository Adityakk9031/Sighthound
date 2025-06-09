# Test Fixtures

This directory contains all the test data and fixtures used by the test suite.

## Directory Structure

- **python/**: Sample Python files for testing Python-specific vulnerabilities
  - Contains both vulnerable and safe code examples
  - Includes Django-specific test files

- **java/**: Sample Java files for testing Java-specific vulnerabilities
  - Contains examples of SQL injection, command injection, weak crypto, etc.

- **javascript/**: Sample JavaScript files for testing JavaScript-specific vulnerabilities

- **rules/**: Test rule files in RON format
  - Used for testing rule loading, parsing, and application

## Usage

These fixtures are used by the tests in the `tests/` directory, which is organized as follows:

- `tests/unit/`: Unit tests for individual components
- `tests/integration/`: Tests that verify multiple components working together
- `tests/end_to_end/`: Tests that verify the entire system functionality

## Adding New Fixtures

When adding new test fixtures:

1. Place them in the appropriate language directory
2. Make sure they have clear names indicating what they're testing
3. Add comments in the file to explain the vulnerabilities or test cases
4. Update this README if adding a new category of fixtures
