#!/usr/bin/env python3
"""
Test file with various security vulnerabilities for scanner testing
"""

import os
import sys
import hashlib
import subprocess
import sqlite3
import json
import random

# SQL Injection vulnerabilities
def vulnerable_sql_query(user_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection
    cursor.execute(query)
    return cursor.fetchall()

def another_sql_vuln(username):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '%s'" % username  # SQL injection with % formatting
    cursor.execute(query)
    return cursor.fetchall()

# Command injection vulnerabilities
def vulnerable_command_execution(filename):
    os.system(f"cat {filename}")  # Command injection
    
def another_command_vuln(user_input):
    subprocess.call("echo " + user_input, shell=True)  # Command injection

# Weak cryptography
def weak_hashing(password):
    return hashlib.md5(password.encode()).hexdigest()  # Weak crypto

def another_weak_crypto(data):
    return hashlib.sha1(data.encode()).hexdigest()  # Weak crypto

# Weak random number generation
def weak_random_token():
    return random.random()  # Weak random

# JSON deserialization (potentially unsafe)
def load_config(config_file):
    with open(config_file, 'r') as f:
        return json.load(f)  # Potential deserialization issue

# Path traversal
def read_file(filename):
    return open(filename, 'r').read()  # Path traversal potential

if __name__ == "__main__":
    print("This is a test file with vulnerabilities") 