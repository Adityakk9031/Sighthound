#!/bin/bash

# Java Rules Testing Script
# Tests the Java vulnerability detection rules against test data

echo "🧪 Testing Java Vulnerability Detection Rules"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TEST_DATA_DIR="$(dirname "$0")/.."
JAVA_TEST_DIR="$TEST_DATA_DIR/java"
RULES_DIR="$TEST_DATA_DIR/test_rules"
MAIN_RULES="rules/java/general.ron"

echo "📂 Test data directory: $JAVA_TEST_DIR"
echo "📋 Rules directory: $RULES_DIR"
echo ""

# Function to run a test
run_test() {
    local test_name="$1"
    local rules_file="$2"
    local expected_count="$3"
    
    echo -n "Testing $test_name... "
    
    # Run the scanner
    result=$(cargo run --quiet "$JAVA_TEST_DIR" java "$rules_file" 2>/dev/null | grep "Total vulnerabilities found:" | grep -o '[0-9]\+')
    
    if [ "$result" = "$expected_count" ]; then
        echo -e "${GREEN}✅ PASS${NC} (found $result vulnerabilities)"
    else
        echo -e "${RED}❌ FAIL${NC} (expected $expected_count, found $result)"
    fi
}

# Function to run detailed test with output
run_detailed_test() {
    local test_name="$1"
    local rules_file="$2"
    
    echo ""
    echo -e "${YELLOW}🔍 $test_name${NC}"
    echo "----------------------------------------"
    cargo run --quiet "$JAVA_TEST_DIR" java "$rules_file"
}

echo "🚀 Running Quick Tests:"

# Test 1: No filtering (should find everything)
run_test "No Filtering Test" "$RULES_DIR/test_no_filtering.ron" "4"

# Test 2: File filtering only
run_test "File Filtering Test" "$RULES_DIR/test_file_filtering.ron" "2"

# Test 3: Main rules (working version)
run_test "Main Java Rules" "$MAIN_RULES" "1"

# Test 4: Basic patterns
run_test "Basic Patterns" "$RULES_DIR/basic_test.ron" "2"

echo ""
echo "🔍 Running Detailed Tests:"

# Detailed test with main rules
run_detailed_test "Main Java Rules (Detailed)" "$MAIN_RULES"

echo ""
echo -e "${GREEN}✅ Java Rules Testing Complete!${NC}" 