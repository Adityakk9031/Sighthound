#!/usr/bin/env python3

import tree_sitter_python as tspython
from tree_sitter import Parser, Language

# Initialize the parser
PY_LANGUAGE = Language(tspython.language())
parser = Parser()
parser.language = PY_LANGUAGE

# Simple test code
test_code = b"""
import os
os.system("hello")
"""

print("Testing tree-sitter parsing...")
tree = parser.parse(test_code)
root_node = tree.root_node

print(f"Root node type: {root_node.type}")
print(f"Root node children: {len(root_node.children)}")

def traverse(node, depth=0):
    indent = "  " * depth
    print(f"{indent}{node.type}: {test_code[node.start_byte:node.end_byte].decode('utf-8', errors='ignore').strip()}")
    for child in node.children:
        traverse(child, depth + 1)

print("\nTree structure:")
traverse(root_node)

print("\nLooking for 'call' nodes:")
def find_calls(node):
    calls = []
    if node.type == 'call':
        calls.append(node)
    for child in node.children:
        calls.extend(find_calls(child))
    return calls

call_nodes = find_calls(root_node)
print(f"Found {len(call_nodes)} call nodes")
for call in call_nodes:
    print(f"Call: {test_code[call.start_byte:call.end_byte].decode('utf-8', errors='ignore').strip()}") 