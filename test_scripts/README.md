# Test Scripts

This directory contains scripts and utilities for testing the vulnerability scanner.

## Available Scripts

- `run_tests.sh`: Main test runner script that runs all tests
- `test_java_rules.sh`: Script for testing Java rules specifically

## Test Report

- `TEST_REPORT.md`: Contains reports from test runs

## Usage

To run all tests:
```bash
./run_tests.sh
```

To run Java-specific tests:
```bash
./test_java_rules.sh
```

## Adding New Scripts

When adding new test scripts:

1. Make the script executable: `chmod +x your_script.sh`
2. Add documentation to this README
3. Consider adding the script to `run_tests.sh` if it should be part of the automated test suite 