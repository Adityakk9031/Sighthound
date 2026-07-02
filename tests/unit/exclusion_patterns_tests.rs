use sighthound::rules::ExclusionPatterns;

#[cfg(test)]
mod exclusion_patterns_tests {
    use super::*;

    fn patterns() -> ExclusionPatterns {
        ExclusionPatterns {
            frontend_exclusions: Some(vec!["*.stories.tsx".to_string()]),
            backend_exclusions: Some(vec!["*_test.go".to_string()]),
            common_exclusions: Some(vec!["*.min.js".to_string()]),
        }
    }

    #[test]
    fn frontend_includes_common_and_frontend_only() {
        let result = patterns().get_patterns("frontend");
        assert_eq!(result, vec!["*.min.js".to_string(), "*.stories.tsx".to_string()]);
    }

    #[test]
    fn backend_includes_common_and_backend_only() {
        let result = patterns().get_patterns("backend");
        assert_eq!(result, vec!["*.min.js".to_string(), "*_test.go".to_string()]);
    }

    #[test]
    fn common_returns_only_common_exclusions() {
        let result = patterns().get_patterns("common");
        assert_eq!(result, vec!["*.min.js".to_string()]);
    }

    #[test]
    fn unknown_pattern_type_returns_empty() {
        let result = patterns().get_patterns("something-else");
        assert!(result.is_empty());
    }

    #[test]
    fn missing_common_exclusions_does_not_panic() {
        let p = ExclusionPatterns {
            frontend_exclusions: Some(vec!["*.snap".to_string()]),
            backend_exclusions: None,
            common_exclusions: None,
        };
        assert_eq!(p.get_patterns("frontend"), vec!["*.snap".to_string()]);
        assert_eq!(p.get_patterns("backend"), Vec::<String>::new());
        assert_eq!(p.get_patterns("common"), Vec::<String>::new());
    }
}
