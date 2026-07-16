//! Tier 1: AST-grounded provenance (Python).
//!
//! Structural assignment shapes must resolve to their real sources instead of
//! text-scan approximations: multiline/annotated/augmented/chained/tuple
//! assignments must not hide taint (false negatives), and docstring text or a
//! same-named variable in another function must not donate taint (false
//! positives).

use super::helpers::*;

const CMD_TAINT_RULES: &str = "tests/strictness/fixtures/command_injection_taint.ron";

#[test]
#[cfg(feature = "python")]
fn multiline_parenthesized_taint_assignment_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "cli.py",
        r#"import os


def run_cli():
    cmd = (
        input()
    )
    os.system(cmd)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        8,
        8,
        1,
        "multiline parenthesized assignment: input() -> os.system must be reported",
    );
}

#[test]
#[cfg(feature = "python")]
fn annotated_taint_assignment_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "annotated.py",
        r#"import os


def run_annotated():
    cmd: str = input()
    os.system(cmd)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        6,
        6,
        1,
        "annotated assignment: input() -> os.system must be reported",
    );
}

#[test]
#[cfg(feature = "python")]
fn augmented_taint_assignment_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "augmented.py",
        r#"import os


def run_augmented():
    cmd = "echo "
    cmd += input()
    os.system(cmd)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        7,
        7,
        1,
        "augmented assignment: cmd += input() -> os.system must be reported",
    );
}

#[test]
#[cfg(feature = "python")]
fn chained_taint_assignment_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "chained.py",
        r#"import os


def run_chained():
    first = second = input()
    os.system(second)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        6,
        6,
        1,
        "chained assignment: the inner chained target must carry taint to os.system",
    );
}

#[test]
#[cfg(feature = "python")]
fn tuple_taint_assignment_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "tuple_target.py",
        r#"import os


def run_tuple():
    cmd, log_name = input(), "app.log"
    os.system(cmd)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        6,
        6,
        1,
        "tuple assignment: tainted tuple element -> os.system must be reported",
    );
}

#[test]
#[cfg(feature = "python")]
fn tuple_safe_sibling_is_not_flagged() {
    // The tainted element (`cmd`) and a safe sibling (`log_name`) are unpacked
    // from the same statement. Using the SAFE sibling at the sink must not be
    // flagged — positional pairing keeps `input()` from bleeding onto `log_name`.
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "tuple_sibling.py",
        r#"import os


def run_tuple():
    cmd, log_name = input(), "app.log"
    os.system(log_name)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_no_findings_in_range(
        &findings,
        1,
        20,
        "safe tuple sibling (log_name = literal) must not inherit the tainted element's value",
    );
}

#[test]
#[cfg(feature = "python")]
fn docstring_text_does_not_taint_real_assignment() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "documented.py",
        r#"import os


def run_documented():
    """Usage:

    cmd = input()
    """
    cmd = "uptime"
    os.system(cmd)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_no_findings_in_range(
        &findings,
        1,
        20,
        "docstring example text must not be treated as the variable's assignment",
    );
}

#[test]
#[cfg(feature = "python")]
fn same_named_variable_in_other_function_does_not_donate_taint() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "scoped.py",
        r#"import os


def collect_input():
    data = input()
    return data


async def report_status():
    data = "uptime"
    os.system("status " + data)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_no_findings_in_range(
        &findings,
        9,
        20,
        "async function's safe local must not inherit taint from another function's same-named variable",
    );
}

#[test]
#[cfg(feature = "python")]
fn iteration_over_literal_collection_is_not_tainted() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "allowlist.py",
        r#"import os


def touch_flags():
    for flag_name in ["beta", "dark_mode", "canary"]:
        os.system("touch /tmp/flag_" + flag_name)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_no_findings_in_range(
        &findings,
        1,
        20,
        "loop variable bound to a literal allowlist must not be treated as attacker-controlled",
    );
}

// Regression guards: these real injections are caught by the text-based engine;
// the AST provenance path must not lose them. An empty-collection initializer
// (`cfg = {}` / `parts = []`) followed by a tainted write must still reach the
// sink.

#[test]
#[cfg(feature = "python")]
fn subscript_write_of_taint_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "subscript.py",
        r#"import os


def run_subscript():
    cfg = {}
    cfg["cmd"] = input("cmd: ")
    os.system(cfg["cmd"])
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        4,
        7,
        1,
        "tainted subscript write into an empty dict must still reach the sink",
    );
}

#[test]
#[cfg(feature = "python")]
fn collection_mutation_with_taint_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "mutation.py",
        r#"import os


def run_mutation():
    parts = []
    parts.append(input("part: "))
    os.system(" ".join(parts))
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        4,
        7,
        1,
        "appending tainted data to an empty list must still reach the sink",
    );
}
