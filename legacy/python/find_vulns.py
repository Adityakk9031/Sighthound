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

def get_file_extension(language_name):
    if language_name == 'python':
        return '.py'
    return ''

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
    # Support for wildcards in patterns
    if '*' in pattern:
        regex = pattern.replace('*', '.*')
        return re.search(f"^{regex}$", text) is not None
    # Support for direct regex if pattern starts with "regex:"
    elif pattern.startswith("regex:"):
        regex = pattern[6:]  # Remove "regex:" prefix
        return re.search(regex, text) is not None
    # Exact match
    else:
        return pattern == text

def check_ast_conditions(node, code, conditions):
    if not conditions:
        return True
        
    # Get parent context for context-aware checks
    parent = node.parent
    
    for condition in conditions:
        condition_type = condition.get('type')
        
        if condition_type == 'has_argument':
            # Check if a specific argument exists or has a pattern
            arg_name = condition.get('name')
            arg_pattern = condition.get('pattern')
            
            args_node = node.child_by_field_name('arguments')
            if not args_node:
                return False
                
            # TODO: Implement argument name matching for keyword arguments
            # For now, just check if any argument matches the pattern
            if arg_pattern:
                for arg in args_node.named_children:
                    arg_text = code[arg.start_byte:arg.end_byte].decode('utf-8', errors='ignore')
                    if match_pattern(arg_pattern, arg_text):
                        return True
                        
        elif condition_type == 'in_context':
            # Check if the node is within a specific context (e.g., not in a comment)
            context = condition.get('not_in', [])
            
            if 'comment' in context and node.parent and node.parent.type == 'comment':
                return False
                
        elif condition_type == 'has_parent':
            # Check if node has a specific parent type
            parent_type = condition.get('parent_type')
            if parent and parent.type != parent_type:
                return False
                
    return True

def check_for_injection_pattern(arg_text):
    # Check for various injection patterns
    patterns = [
        # String formatting
        r'%[sdfir]', r'\{.*?\}', r'\.format\(',
        # String concatenation
        r'[\'"][^\'"]* \+ ',
        # f-strings
        r'f[\'"]',
        # Shell command injection patterns
        r';', r'&&', r'\|\|', r'\$\(', r'`.*?`'
    ]
    
    for pattern in patterns:
        if re.search(pattern, arg_text):
            return True
            
    return False

def scan_file(filepath, code, root_node, rules):
    findings = []

    for node in traverse(root_node):
        if node.type == 'call':
            func_name = get_func_name(node, code)
            if not func_name:
                continue
                
            # Check each rule category
            for category, rule_set in rules.items():
                for rule in rule_set:
                    # Get pattern and conditions
                    pattern = rule.get('pattern', '')
                    conditions = rule.get('conditions', [])
                    finding_type = rule.get('finding_type', category)
                    
                    # Check if function name matches pattern
                    if match_pattern(pattern, func_name):
                        # Check any additional AST conditions
                        if check_ast_conditions(node, code, conditions):
                            # For injection rules, check arguments
                            if category == 'injection_sinks':
                                args_node = node.child_by_field_name('arguments')
                                if args_node:
                                    for arg in args_node.named_children:
                                        arg_text = code[arg.start_byte:arg.end_byte].decode('utf-8', errors='ignore')
                                        if check_for_injection_pattern(arg_text):
                                            findings.append({
                                                'file': filepath,
                                                'line': node.start_point[0] + 1,
                                                'function': func_name,
                                                'finding_type': finding_type,
                                                'code': code[node.start_byte:node.end_byte].decode('utf-8', errors='ignore').strip()
                                            })
                                            break
                            else:
                                # For other rules, just add the finding
                                findings.append({
                                    'file': filepath,
                                    'line': node.start_point[0] + 1,
                                    'function': func_name,
                                    'finding_type': finding_type,
                                    'code': code[node.start_byte:node.end_byte].decode('utf-8', errors='ignore').strip()
                                })

    return findings

def find_vulnerabilities(root_dir, language_name, rules):
    if language_name != 'python':
        raise ValueError("This script currently supports only Python")

    parser = Parser()
    parser.language = PY_LANGUAGE

    findings = []

    for subdir, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(get_file_extension(language_name)):
                filepath = os.path.join(subdir, file)
                with open(filepath, 'rb') as f:
                    code = f.read()

                tree = parser.parse(code)
                root_node = tree.root_node

                findings.extend(scan_file(filepath, code, root_node, rules))

    return findings

def main():
    if len(sys.argv) != 4:
        print("Usage: python find_vulns.py <root_dir> <language> <rules_file>")
        sys.exit(1)

    root_dir = sys.argv[1]
    language_name = sys.argv[2].lower()
    rules_file = sys.argv[3]

    rules = load_rules(rules_file)
    findings = find_vulnerabilities(root_dir, language_name, rules)

    print("Starting Scan! -----------------")

    # Print individual findings
    for finding in findings:
        print(f"{finding['file']}:{finding['line']} - {finding['finding_type']} - {finding['function']}")
    
    # Generate and print summary
    print("\nVulnerability Summary -----------------")
    
    # Count findings by type
    finding_types = {}
    for finding in findings:
        finding_type = finding['finding_type']
        if finding_type in finding_types:
            finding_types[finding_type] += 1
        else:
            finding_types[finding_type] = 1
    
    # Print summary by finding type
    for finding_type, count in sorted(finding_types.items()):
        print(f"{finding_type}: {count} occurrences")
    
    # Print files with most vulnerabilities
    file_counts = {}
    for finding in findings:
        file_path = finding['file']
        if file_path in file_counts:
            file_counts[file_path] += 1
        else:
            file_counts[file_path] = 1
    
    print("\nMost vulnerable files:")
    for file_path, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{file_path}: {count} vulnerabilities")
    
    print(f"\nTotal vulnerabilities found: {len(findings)}")

if __name__ == "__main__":
    main()