Feature: JavaScript XSS taint detection

  Frontend taint rules must follow untrusted DOM/URL data into innerHTML-style
  sinks and flag the resulting XSS.

  Scenario: innerHTML taint flow from DOM and URL sources is detected
    Given a staged copy of the fixture "tests/test_files/javascript/xss_simple_test.js" as "xss_case.js"
    When I scan the staging directory as "javascript" with the frontend taint rules
    Then the findings should include a taint finding in "xss_case.js"
    And the findings should include a finding whose type contains "XSS" in "xss_case.js"
