// Unit tests for the vulnerability scanner
mod django_xss_prevention_tests;
mod injection_pattern_tests;
// TODO(onboarding): file_pattern_tests uses removed Rules::malware_detection schema; needs triage
// mod file_pattern_tests;
// TODO(onboarding): directory_loading_tests uses removed Rules::malware_detection schema; needs triage
// mod directory_loading_tests;
// TODO(onboarding): rule_deserialization_tests uses removed Rules::malware_detection schema; needs triage
// mod rule_deserialization_tests;
// TODO(onboarding): pattern_matching_tests uses removed Rule struct and rule_matches_pattern/validate_rule_patterns fns; needs triage
// mod pattern_matching_tests;
mod javascript_ron_parser_tests;
mod javascript_rules_tests;
