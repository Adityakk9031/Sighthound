# Fixture for #40: allowlist-bounded access patterns — must produce zero taint findings.
# These are the FP classes reported in the issue: fixed allowlists, bounded comparison
# data, boolean-coerced values, and fixed-key copies.
from flask import request

ALLOWED_FIELDS = ["name", "email", "role", "phone"]
OP_MAP = {"eq": "=", "lt": "<", "gt": ">", "gte": ">=", "lte": "<="}
SAFE_FLAGS = {"active", "verified", "admin"}


def filter_to_allowlist(user_data):
    # Keys come from a fixed allowlist — attacker controls values but not which
    # fields are copied. Not a vulnerability.
    return {k: user_data.get(k) for k in ALLOWED_FIELDS}


def safe_op_lookup(op_name):
    # op_name may be user-supplied, but the result is bounded to values in OP_MAP.
    # OP_MAP is a constant dict — lookup output is always one of 5 fixed strings.
    return OP_MAP.get(op_name, "=")


def coerce_bool_flags(flags):
    # Values coerced to bool — result is always True/False regardless of input.
    # Keys are constrained to SAFE_FLAGS.
    return {k: bool(flags.get(k, False)) for k in SAFE_FLAGS}


def copy_fixed_keys(source):
    # Only five fixed keys are ever copied; no freeform key passthrough.
    result = {}
    for k in ALLOWED_FIELDS:
        if k in source:
            result[k] = source[k]
    return result


def api_handler():
    data = request.json
    # All of the above used with a real request source — still no injection sink.
    fields = filter_to_allowlist(data)
    op = safe_op_lookup(data.get("op", "eq"))
    flags = coerce_bool_flags(data.get("flags", {}))
    return {"fields": fields, "op": op, "flags": flags}
