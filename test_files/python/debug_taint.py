#!/usr/bin/env python3
"""
Simple taint test file to debug detection
"""

import os
import sys

# Simple taint flow that should be detected
user_input = os.environ.get('USER_DATA', '')  # Tainted source: os.environ
eval(user_input)  # Vulnerable sink: eval()

# Another simple flow
cmd_arg = sys.argv[1] if len(sys.argv) > 1 else ''  # Tainted source: sys.argv
exec(cmd_arg)  # Vulnerable sink: exec()

# Direct pattern
config = os.environ.get('CONFIG', '')
eval(config) 