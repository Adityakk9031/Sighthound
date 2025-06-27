use crate::rules::FileTypes;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use anyhow::Result;
use walkdir::WalkDir;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use crate::skip::SKIP_DIRS;

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
pub fn rule_applies_to_file(file_types: Option<&FileTypes>, file_path: &str) -> bool {
    // If no file types specified, rule applies to all files
    let Some(file_types) = file_types else {
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
pub fn rule_applies_to_file_path(file_types: Option<&FileTypes>, file_path: &Path) -> bool {
    let file_path_str = file_path.to_string_lossy();
    rule_applies_to_file(file_types, &file_path_str)
}

/// Detect programming language from file path
pub fn detect_language_from_path(file_path: &Path) -> Option<&'static str> {
    match file_path.extension()?.to_str()? {
        "py" => Some("python"),
        "java" => Some("java"),
        "js" | "mjs" => Some("javascript"),
        "tsx" => Some("tsx"),
        "html" => {
            let path_str = file_path.to_string_lossy().to_lowercase();
            if path_str.contains("template") || path_str.contains("django") {
                Some("html")
            } else {
                Some("html")
            }
        },
        _ => None,
    }
}

/// Discover files by language using parallel processing
pub fn discover_files_by_language_parallel(root_dir: &str) -> Result<HashMap<String, Vec<PathBuf>>> {
    let all_paths: Vec<PathBuf> = WalkDir::new(root_dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if e.file_type().is_dir() {
                if let Some(name) = e.file_name().to_str() {
                    return !SKIP_DIRS.contains(&name);
                }
            }
            true
        })
        .par_bridge()
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                if e.path().is_file() {
                    Some(e.path().to_path_buf())
                } else { None }
            })
        })
        .collect();
    
    let estimated_languages = 6;
    let estimated_files_per_lang = if all_paths.is_empty() { 
        50 
    } else { 
        (all_paths.len() / estimated_languages).max(50) 
    };
    
    println!("📂 Discovered {} files total, estimating {} files per language", 
             all_paths.len(), estimated_files_per_lang);
    
    let files_by_language = Arc::new(Mutex::new(
        HashMap::<String, Vec<PathBuf>>::with_capacity(estimated_languages)
    ));
    
    all_paths.par_iter().for_each(|path| {
        if let Some(language) = detect_language_from_path(path) {
            let mut map = files_by_language.lock().unwrap();
            map.entry(language.to_string())
                .or_insert_with(|| Vec::with_capacity(estimated_files_per_lang))
                .push(path.clone());
        }
    });
    
    Ok(Arc::try_unwrap(files_by_language).unwrap().into_inner().unwrap())
}

/// Discover files by language using sequential processing
pub fn discover_files_by_language_sequential(root_dir: &str) -> Result<HashMap<String, Vec<PathBuf>>> {
    let mut files_by_language = HashMap::with_capacity(6);
    
    for entry in WalkDir::new(root_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().is_file() {
            if let Some(language) = detect_language_from_path(entry.path()) {
                files_by_language
                    .entry(language.to_string())
                    .or_insert_with(|| Vec::with_capacity(100))
                    .push(entry.path().to_path_buf());
            }
        }
    }
    
    Ok(files_by_language)
} 