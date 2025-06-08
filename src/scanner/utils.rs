use crate::rules::Rule;
use std::path::Path;

/// Check if a file path matches a glob pattern
pub fn matches_glob_pattern(pattern: &str, file_path: &str) -> bool {
    use glob::Pattern;
    
    // Try exact glob pattern matching first (full path)
    if let Ok(glob_pattern) = Pattern::new(pattern) {
        if glob_pattern.matches(file_path) {
            return true;
        }
        
        // Also try matching against just the filename
        if let Some(filename) = std::path::Path::new(file_path).file_name() {
            if let Some(filename_str) = filename.to_str() {
                if glob_pattern.matches(filename_str) {
                    return true;
                }
            }
        }
    }

    // Fallback to simple wildcard matching (for backward compatibility)
    if pattern.contains('*') {
        let regex_pattern = pattern.replace('*', ".*");
        if let Ok(regex) = regex::Regex::new(&format!("^{}$", regex_pattern)) {
            // Try full path
            if regex.is_match(file_path) {
                return true;
            }
            // Try just filename
            if let Some(filename) = std::path::Path::new(file_path).file_name() {
                if let Some(filename_str) = filename.to_str() {
                    if regex.is_match(filename_str) {
                        return true;
                    }
                }
            }
        }
    }

    // Exact string match - check both full path and filename
    if file_path.contains(pattern) {
        return true;
    }
    if let Some(filename) = std::path::Path::new(file_path).file_name() {
        if let Some(filename_str) = filename.to_str() {
            if filename_str.contains(pattern) {
                return true;
            }
        }
    }

    false
}

/// Check if a rule applies to a given file path based on file type constraints
pub fn rule_applies_to_file(rule: &Rule, file_path: &str) -> bool {
    // If no file types specified, rule applies to all files
    let Some(file_types) = &rule.file_types else {
        return true;
    };

    // Check include patterns first
    if let Some(include_patterns) = &file_types.include_patterns {
        let mut matches_include = false;
        for pattern in include_patterns {
            if matches_glob_pattern(pattern, file_path) {
                matches_include = true;
                break;
            }
        }
        if !matches_include {
            return false;
        }
    }

    // Check exclude patterns
    if let Some(exclude_patterns) = &file_types.exclude_patterns {
        for pattern in exclude_patterns {
            if matches_glob_pattern(pattern, file_path) {
                return false;
            }
        }
    }

    // Check extensions
    if let Some(extensions) = &file_types.extensions {
        if let Some(file_extension) = Path::new(file_path).extension() {
            if let Some(ext_str) = file_extension.to_str() {
                let ext_with_dot = format!(".{}", ext_str);
                if !extensions.contains(&ext_str.to_string()) && !extensions.contains(&ext_with_dot) {
                    return false;
                }
            }
        } else {
            // File has no extension, but rule requires specific extensions
            return false;
        }
    }

    true
}

/// Helper function to check if file types match (for Path-based version)
pub fn rule_applies_to_file_path(rule: &Rule, file_path: &Path) -> bool {
    let file_path_str = file_path.to_string_lossy();
    rule_applies_to_file(rule, &file_path_str)
} 