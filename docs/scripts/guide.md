# Writing Custom Risk Rules with Scripts

This guide walks you through creating custom risk rules using the Threagile YAML-based script language. For a complete language reference, see [language-reference.md](./language-reference.md). For testing your scripts, see [testing.md](./testing.md).

## Overview

Instead of writing risk rules in Go and compiling them as plugins, you can define risk rules as YAML scripts. These scripts are loaded at runtime and evaluated against the threat model just like built-in rules.

Script files are placed in the risk scripts directory (e.g., `pkg/risks/scripts/`) and have the `.yaml` extension.

## Quick Start

Here is a minimal risk rule that flags all in-scope technical assets tagged with `database`:

```yaml
id: unencrypted-database
title: Unencrypted Database
function: operations
stride: information-disclosure
cwe: 311
description: >
  Databases should encrypt data at rest to protect against unauthorized access.
impact: >
  If unmitigated, sensitive data could be exposed through physical access or backup theft.
asvs: "V8 - Data Protection Verification Requirements"
cheat_sheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
action: "Database Encryption"
mitigation: >
  Enable transparent data encryption (TDE) or use encrypted storage volumes.
check: "Is data-at-rest encryption enabled for all databases?"
detection_logic: >
  In-scope technical assets tagged with 'database'.
risk_assessment: >
  The risk rating depends on the confidentiality of processed data assets.
false_positives: >
  Databases that only store public, non-sensitive data.

risk:
  id:
    parameter: tech_asset
    id: "{$risk.id}@{tech_asset.id}"

  match:
    parameter: tech_asset
    do:
      - if:
          and:
            - false: "{tech_asset.out_of_scope}"
            - contains:
                item: database
                in: "{tech_asset.tags}"
          then:
            return: true

  data:
    parameter: tech_asset
    title: "<b>Unencrypted Database</b> risk at <b>{tech_asset.title}</b>"
    severity: "calculate_severity(likely, medium)"
    exploitation_likelihood: likely
    exploitation_impact: medium
    data_breach_probability: probable
    data_breach_technical_assets:
      - "{tech_asset.id}"
    most_relevant_technical_asset: "{tech_asset.id}"
```

## Step-by-Step Guide

### Step 1: Define the Risk Category Metadata

Start with the top-level fields that describe the risk category. These fields map directly to the `RiskCategory` type:

```yaml
id: my-rule-id              # unique identifier, used in risk tracking
title: My Rule Title         # human-readable title
function: operations         # business-side | architecture | development | operations
stride: information-disclosure  # which STRIDE category
cwe: 200                    # CWE number
```

The remaining metadata fields provide context for reports:

```yaml
description: >
  What this risk is about.
impact: >
  What happens if unmitigated.
asvs: "ASVS chapter reference"
cheat_sheet: "URL to relevant OWASP cheat sheet"
action: "Short action title"
mitigation: >
  How to mitigate. Supports <i>HTML</i> for emphasis.
check: "Verification question?"
detection_logic: >
  When this rule triggers.
risk_assessment: >
  How severity is determined.
false_positives: >
  Known false positive scenarios.
```

### Step 2: Define the Match Condition

The `match:` section filters which technical assets trigger a risk. The engine iterates over **all** technical assets and calls your match logic for each one.

**Common patterns:**

Filter by technology attribute:
```yaml
match:
  parameter: tech_asset
  do:
    - if:
        and:
          - false: "{tech_asset.out_of_scope}"
          - any:
              in: "{tech_asset.technologies}"
              true: "{.attributes.web-application}"
        then:
          return: true
```

Filter by tag:
```yaml
match:
  parameter: tech_asset
  do:
    - if:
        and:
          - false: "{tech_asset.out_of_scope}"
          - contains:
              item: my-tag
              in: "{tech_asset.tags}"
        then:
          return: true
```

Filter by multiple conditions using `or`:
```yaml
match:
  parameter: tech_asset
  do:
    - if:
        and:
          - false: "{tech_asset.out_of_scope}"
          - or:
              - contains:
                  item: database
                  in: "{tech_asset.tags}"
              - any:
                  in: "{tech_asset.technologies}"
                  true: "{.attributes.database}"
        then:
          return: true
```

### Step 3: Define the Risk Data

The `data:` section defines the fields of the generated risk object. Each field is evaluated as an expression.

For simple cases with fixed severity:
```yaml
data:
  parameter: tech_asset
  title: "<b>My Rule</b> risk at <b>{tech_asset.title}</b>"
  severity: "calculate_severity(unlikely, low)"
  exploitation_likelihood: unlikely
  exploitation_impact: low
  data_breach_probability: possible
  data_breach_technical_assets:
    - "{tech_asset.id}"
  most_relevant_technical_asset: "{tech_asset.id}"
```

For dynamic severity based on data asset classification, use a utility method (see Step 4).

### Step 4: Add Utility Methods

For non-trivial logic, extract reusable methods into the `utils:` section.

**Dynamic impact calculation** based on processed data assets:

```yaml
utils:
  get_impact:
    parameters:
      - tech_asset
    do:
      - assign:
          - impact: low
          - highest_confidentiality: "get_highest({tech_asset}, confidentiality)"
          - highest_integrity: "get_highest({tech_asset}, integrity)"
          - highest_availability: "get_highest({tech_asset}, availability)"
      - if:
          or:
            - equal-or-greater:
                as: confidentiality
                first: "{highest_confidentiality}"
                second: confidential
            - equal-or-greater:
                as: criticality
                first: "{highest_integrity}"
                second: critical
            - equal-or-greater:
                as: criticality
                first: "{highest_availability}"
                second: critical
          then:
            - assign:
                impact: medium
      - if:
          or:
            - equal-or-greater:
                as: confidentiality
                first: "{highest_confidentiality}"
                second: strictly-confidential
            - equal-or-greater:
                as: criticality
                first: "{highest_integrity}"
                second: mission-critical
            - equal-or-greater:
                as: criticality
                first: "{highest_availability}"
                second: mission-critical
          then:
            - assign:
                impact: high
      - return: "{impact}"

  get_highest:
    parameters:
      - tech_asset
      - "type"
    do:
      - assign:
          - value: "{tech_asset.{type}}"
      - loop:
          in: "{tech_asset.data_assets_processed}"
          item: data_id
          do:
            if:
              greater:
                first: "{$model.data_assets.{data_id}.{type}}"
                second: "{value}"
                as: "{type}"
              then:
                - assign:
                    value: "{$model.data_assets.{data_id}.{type}}"
      - return: "{value}"
```

Then reference it from the `data:` section:

```yaml
data:
  parameter: tech_asset
  title: "get_title({tech_asset})"
  severity: "calculate_severity(unlikely, get_impact({tech_asset}))"
  exploitation_likelihood: unlikely
  exploitation_impact: "get_impact({tech_asset})"
  # ...
```

**Dynamic title** based on asset tags:

```yaml
utils:
  get_title:
    parameters:
      - tech_asset
    do:
      - if:
          contains:
            item: git
            in: "{tech_asset.tags}"
          then:
            - return:
                "<b>Accidental Secret Leak (Git)</b> risk at <b>{tech_asset.title}</b>: <u>Git Leak Prevention</u>"
          else:
            - return:
                "<b>Accidental Secret Leak</b> risk at <b>{tech_asset.title}</b>"
```

### Step 5: Add Explanations (Optional)

Add `explain` statements and `defer` blocks to provide audit trails for why a risk was generated and how the severity was determined.

```yaml
get_highest:
  parameters:
    - tech_asset
    - "type"
  do:
    - defer:
        - explain: "the highest {type} value of the technical asset is '{value}'"
    - assign:
        - value: "{tech_asset.{type}}"
    - explain: "{type} value of the technical asset is '{value}'"
    - loop:
        in: "{tech_asset.data_assets_processed}"
        item: data_id
        do:
          if:
            greater:
              first: "{$model.data_assets.{data_id}.{type}}"
              second: "{value}"
              as: "{type}"
            then:
              - assign:
                  value: "{$model.data_assets.{data_id}.{type}}"
              - explain: "{type} value of data asset '{data_id}' is '{value}'"
    - return: "{value}"
```

`explain` records a fact at the point of execution. `defer` ensures the explanation runs when the method exits, giving it access to the final variable values.

## Complete Example

See the reference implementation: [`pkg/risks/scripts/accidental-secret-leak.yaml`](../../pkg/risks/scripts/accidental-secret-leak.yaml)

This script implements the same logic as the Go built-in rule at `pkg/risks/builtin/accidental_secret_leak_rule.go`, providing a side-by-side comparison of both approaches.

## Common Patterns

### Check Technology Attributes

```yaml
any:
  in: "{tech_asset.technologies}"
  or:
    - true: "{.attributes.web-application}"
    - true: "{.attributes.web-service-rest}"
```

### Check Data Asset Properties via Model

```yaml
- loop:
    in: "{tech_asset.data_assets_processed}"
    item: data_id
    do:
      if:
        equal:
          first: "{$model.data_assets.{data_id}.confidentiality}"
          second: strictly-confidential
        then:
          - assign:
              has_sensitive_data: true
```

### Conditional Title Suffix

```yaml
- if:
    contains:
      item: some-tag
      in: "{tech_asset.tags}"
    then:
      - return: "<b>{$risk.title} (Special)</b> risk at <b>{tech_asset.title}</b>: <u>Details</u>"
    else:
      - return: "<b>{$risk.title}</b> risk at <b>{tech_asset.title}</b>"
```

### Combining Multiple Data Asset Loops

```yaml
- loop:
    in: "{tech_asset.data_assets_processed}"
    item: processed_id
    do:
      # check processed assets
- loop:
    in: "{tech_asset.data_assets_stored}"
    item: stored_id
    do:
      # check stored assets
```

## Tips

- Always check `false: "{tech_asset.out_of_scope}"` in your match condition to respect scoping.
- Use `as` in comparison expressions when comparing enum values (confidentiality, criticality, etc.) — without it, the comparison is a plain string comparison.
- Method names in `utils:` are case-insensitive.
- Variable names are case-insensitive.
- The `{.field}` syntax only works inside `loop` and `any`/`all`/`count` iterations to reference the current item.
- String values support HTML tags for formatting in report output (`<b>`, `<i>`, `<u>`).
- Use `calculate_severity(likelihood, impact)` to compute severity consistently with Threagile's built-in calculation.
