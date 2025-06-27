pub const SKIP_DIRS: &[&str] = &[
    "venv", "env", ".venv", ".env",
    "node_modules", ".git",
    "__pycache__", ".pytest_cache",
    "target", "build", "dist",
    ".idea", ".vscode",
];

/// File patterns for minified/bundled JavaScript files
pub const SKIP_MINIFIED_PATTERNS: &[&str] = &[
    "*.min.js", "*.min.jsx", "*.min.ts", "*.min.tsx",
    "*.bundle.js", "*.chunk.js", "*.vendor.js", "*.webpack.js",
    "*-min.js", "*-bundle.js", "*-compiled.js", "*-uglified.js",
    "*-compressed.js", "*.pack.js", "*.prod.js"
]; 