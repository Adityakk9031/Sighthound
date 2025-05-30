#!/usr/bin/env python3

import os
import sys
import json
import re
import tree_sitter_python as tspython
from tree_sitter import Parser, Language

# Load Python grammar
PY_LANGUAGE = Language(tspython.language())

def load_rules(rules_file):
    with open(rules_file, 'r') as f:
        return json.load(f)

def traverse(node):
    yield node
    for child in node.children:
        yield from traverse(child)

def get_func_name(node, code):
    func_node = node.child_by_field_name('function')
    if func_node:
        return code[func_node.start_byte:func_node.end_byte].decode('utf-8', errors='ignore')
    return None

def match_pattern(pattern, text):
    print(f"  Checking pattern '{pattern}' against '{text}'")
    # Support for wildcards in patterns
    if '*' in pattern:
        regex = pattern.replace('*', '.*')
        result = re.search(f"^{regex}$", text) is not None
        print(f"    Wildcard result: {result}")
        return result
    # Support for direct regex if pattern starts with "regex:"
    elif pattern.startswith("regex:"):
        regex = pattern[6:]  # Remove "regex:" prefix
        result = re.search(regex, text) is not None
        print(f"    Regex result: {result}")
        return result
    # Exact match
    else:
        result = pattern == text
        print(f"    Exact match result: {result}")
        return result

def main():
    if len(sys.argv) != 4:
        print("Usage: python debug_scanner.py <file> <language> <rules_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    language_name = sys.argv[2].lower()
    rules_file = sys.argv[3]

    rules = load_rules(rules_file)
    print(f"Loaded rules: {list(rules.keys())}")
    
    parser = Parser()
    parser.language = PY_LANGUAGE

    with open(file_path, 'rb') as f:
        code = f.read()

    tree = parser.parse(code)
    root_node = tree.root_node

    print(f"Parsed file {file_path}")
    print(f"Root node: {root_node.type}")

    # Look for call nodes
    call_nodes = []
    for node in traverse(root_node):
        if node.type == 'call':
            call_nodes.append(node)
            func_name = get_func_name(node, code)
            print(f"Found call: {func_name}")
            
            # Check against rules
            for category, rule_set in rules.items():
                print(f"  Checking category: {category}")
                for rule in rule_set:
                    pattern = rule.get('pattern', '')
                    if match_pattern(pattern, func_name):
                        print(f"    MATCH! Rule: {rule}")

    print(f"Total call nodes found: {len(call_nodes)}")

if __name__ == "__main__":
    main() 