Feature: False-positive floor

  Ordinary application code with no dangerous sinks must not generate any
  findings under the production rules.

  Scenario: A benign Python module produces zero findings
    Given a staged benign Python module "calculator.py"
    When I scan the staging directory as "python" with the production rules
    Then no findings should be reported
