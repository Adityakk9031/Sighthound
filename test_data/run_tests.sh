#!/bin/bash

# Greppy Unified Test Suite Runner
# This script runs all tests in the unified test suite

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $message"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $message"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
    esac
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

# Function to run a test and check results
run_test() {
    local test_name=$1
    local command=$2
    local expected_pattern=$3
    local description=$4
    
    print_status "INFO" "Running $test_name: $description"
    
    if output=$(eval "$command" 2>&1); then
        if [[ -n "$expected_pattern" ]] && echo "$output" | grep -q "$expected_pattern"; then
            print_status "PASS" "$test_name completed successfully"
            return 0
        elif [[ -z "$expected_pattern" ]]; then
            print_status "PASS" "$test_name completed successfully"
            return 0
        else
            print_status "FAIL" "$test_name did not produce expected output"
            echo "Expected: $expected_pattern"
            echo "Output: $output" | head -5
            return 1
        fi
    else
        print_status "FAIL" "$test_name failed to execute"
        echo "Error: $output" | head -5
        return 1
    fi
}

# Check if binary exists
if [ ! -f "./target/release/find_vulns" ]; then
    print_status "FAIL" "Binary not found. Please run 'cargo build --release' first"
    exit 1
fi

print_status "INFO" "Starting Greppy Unified Test Suite"
print_status "INFO" "=================================="

# 1. Rust Unit Tests
print_status "INFO" "Running Rust unit and integration tests..."
if cargo test --quiet > /dev/null 2>&1; then
    print_status "PASS" "Rust unit tests"
else
    print_status "FAIL" "Rust unit tests"
fi

# 2. Django Rules Tests
print_status "INFO" "Testing Django vulnerability detection..."

run_test "django_scan" \
    "./target/release/find_vulns test_data/python/django python rules/python/django/ --threads 1" \
    "Scan completed" \
    "Django rules loading and scanning"

# 3. General Python Tests
print_status "INFO" "Testing general Python vulnerability detection..."

run_test "general_eval" \
    "./target/release/find_vulns test_data/python/general/simple_eval.py python rules/python/python/general.ron --threads 1" \
    "eval" \
    "Basic eval vulnerability detection"

run_test "general_bulk" \
    "./target/release/find_vulns test_data/python/general python rules/python/python/general.ron --threads 1" \
    "Scan completed" \
    "Bulk general Python scanning"

# 4. Malicious Pattern Tests
print_status "INFO" "Testing malicious pattern detection..."

run_test "malicious_patterns" \
    "./target/release/find_vulns test_data/python/malicious python rules/python/malicious/ --threads 1" \
    "Scan completed" \
    "Malicious pattern detection"

# 5. Performance Tests
print_status "INFO" "Testing performance optimizations..."

run_test "parser_pooling" \
    "./target/release/find_vulns test_data/python python rules/python/python/general.ron --threads 4" \
    "Created parser pool" \
    "Parser pooling functionality"

run_test "prefiltering" \
    "./target/release/find_vulns test_data/python/general python rules/python/django/ --threads 1" \
    "Pre-filter.*reduction" \
    "Pre-filtering functionality"

# 6. Rule Syntax Tests
print_status "INFO" "Testing rule syntax validation..."

if [ -f "test_data/test_clean_syntax.ron" ]; then
    run_test "rule_syntax" \
        "./target/release/find_vulns test_data/python/general python test_data/test_clean_syntax.ron --threads 1" \
        "Running scan" \
        "Rule syntax validation"
fi

# 7. Edge Case Tests
print_status "INFO" "Testing edge cases..."

run_test "empty_directory" \
    "mkdir -p empty_test && ./target/release/find_vulns empty_test python rules/python/python/general.ron --threads 1 2>/dev/null; rmdir empty_test" \
    "No files found" \
    "Empty directory handling"

# Print Summary
print_status "INFO" "=================================="
print_status "INFO" "Test Suite Summary"
print_status "INFO" "Total Tests: $TOTAL_TESTS"
print_status "INFO" "Passed: $PASSED_TESTS"
print_status "INFO" "Failed: $FAILED_TESTS"

if [ $FAILED_TESTS -eq 0 ]; then
    print_status "PASS" "All tests passed! 🎉"
    exit 0
else
    print_status "FAIL" "$FAILED_TESTS tests failed"
    exit 1
fi 