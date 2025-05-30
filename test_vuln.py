#!/usr/bin/env python3
import os
import subprocess
import sqlite3
import random
import hashlib

def test_command_injection():
    """Test function with command injection vulnerabilities"""
    user_input = input("Enter filename: ")
    
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    
    # Command injection vulnerabilities
    os.system(f"ls {user_input}")
    subprocess.call(f"cat {user_input}", shell=True)
    os.popen(f"grep pattern {user_input}")
    
def test_crypto_issues():
    """Test function with cryptographic vulnerabilities"""
    # Weak random number generation
    weak_random = random.random()
    weak_token = str(random.randint(1, 1000))
    
    # Weak hashing (MD5)
    password = "secret123"
    weak_hash = hashlib.md5(password.encode()).hexdigest()
    
    return weak_random, weak_token, weak_hash

def test_hardcoded_secrets():
    """Test function with hardcoded secrets"""
    api_key = "sk-1234567890abcdef"
    password = "admin123"
    secret_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
    
    return api_key, password, secret_token

def test_path_traversal():
    """Test function with path traversal vulnerabilities"""
    filename = input("Enter file to read: ")
    
    with open(f"/var/log/{filename}", 'r') as f:
        content = f.read()
    
    return content

if __name__ == "__main__":
    test_command_injection()
    test_crypto_issues()
    test_hardcoded_secrets()
    test_path_traversal() 