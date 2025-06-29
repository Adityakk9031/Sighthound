pub const SKIP_DIRS: &[&str] = &[
    "venv", "env", ".venv", ".env",
    "node_modules", ".git",
    "__pycache__", ".pytest_cache",
    "target", "build", "dist",
    ".idea", ".vscode",
    "tests", "test", // Skip test directories
];

/// File patterns for minified/bundled JavaScript files
pub const SKIP_MINIFIED_PATTERNS: &[&str] = &[
    "*.min.js", "*.min.jsx", "*.min.ts", "*.min.tsx",
    "*.bundle.js", "*.chunk.js", "*.vendor.js", "*.webpack.js",
    "*-min.js", "*-bundle.js", "*-compiled.js", "*-uglified.js",
    "*-compressed.js", "*.pack.js", "*.prod.js"
];

/// Test file patterns to skip during taint analysis
pub const SKIP_TEST_PATTERNS: &[&str] = &[
    "test_*.py", "*_test.py", "test*.py",
    "test_*.js", "*_test.js", "*.test.js",
    "*.spec.js", "*.spec.py",
    "conftest.py", "**/tests/**",
    "**/test/**", "**/*test*/**",
]; 