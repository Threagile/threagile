# Threagile Risk Script Language Reference

The Threagile risk script engine allows you to define custom risk rules as YAML files instead of writing Go code. Scripts are loaded from YAML files and evaluated against the threat model at runtime.

## File Structure

A risk script YAML file consists of two main parts: the **risk category metadata** (top-level fields) and the **risk logic** (under the `risk:` key).

```yaml
# --- Risk Category Metadata ---
id: my-custom-rule
title: My Custom Rule
function: operations          # one of: business-side, architecture, development, operations
stride: information-disclosure # STRIDE category
cwe: 200                      # CWE identifier (integer)
description: |
  Description of the risk.
impact: |
  What happens if this risk is unmitigated.
asvs: "V14 - Configuration Verification Requirements"
cheat_sheet: "https://example.com/cheat-sheet"
action: "Recommended Action Title"
mitigation: |
  How to mitigate this risk.
check: "Question to verify mitigation?"
detection_logic: |
  When this rule triggers.
risk_assessment: |
  How the risk rating is determined.
false_positives: |
  Known false positive scenarios.

# Optional
supported-tags:
  - git
  - nexus

# --- Risk Logic ---
risk:
  id:
    # ...
  match:
    # ...
  data:
    # ...
  utils:
    # ...
```

## The `risk:` Section

The `risk:` section contains four subsections that define the script logic:

### `id:` — Risk Identifier

Defines how the synthetic risk ID is constructed.

```yaml
id:
  parameter: tech_asset
  id: "{$risk.id}@{tech_asset.id}"
```

- **parameter**: Names the argument passed to this section (the current technical asset).
- **id**: A string expression that produces the unique risk ID. Use `{$risk.id}` to reference the risk category ID and `{tech_asset.id}` to reference asset properties.

### `match:` — Filter Condition

Determines which technical assets this rule applies to. The engine iterates over all technical assets in the model and calls `match:` for each one. If `match:` returns `true`, a risk is generated for that asset.

```yaml
match:
  parameter: tech_asset
  do:
    - if:
        and:
          - false: "{tech_asset.out_of_scope}"
          - any:
              in: "{tech_asset.technologies}"
              or:
                - true: "{.attributes.sourcecode-repository}"
                - true: "{.attributes.artifact-registry}"
        then:
          return: true
```

- **parameter**: Names the technical asset argument.
- **do**: A list of statements to execute. Must `return: true` for matching assets.

### `data:` — Risk Data Template

Defines the fields of the generated risk object.

```yaml
data:
  parameter: tech_asset
  title: "get_title({tech_asset})"
  severity: "calculate_severity(unlikely, get_impact({tech_asset}))"
  exploitation_likelihood: unlikely
  exploitation_impact: "get_impact({tech_asset})"
  data_breach_probability: probable
  data_breach_technical_assets:
    - "{tech_asset.id}"
  most_relevant_technical_asset: "{tech_asset.id}"
```

Available risk data fields:

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | Risk title (supports HTML: `<b>`, `<u>`, `<i>`) |
| `severity` | string | Calculated severity (use `calculate_severity()`) |
| `exploitation_likelihood` | string | One of: `unlikely`, `likely`, `very-likely`, `frequent` |
| `exploitation_impact` | string | One of: `low`, `medium`, `high`, `very-high` |
| `data_breach_probability` | string | One of: `improbable`, `possible`, `probable` |
| `data_breach_technical_assets` | list | Technical asset IDs affected by a breach |
| `most_relevant_technical_asset` | string | Primary technical asset ID |

### `utils:` — Helper Methods

Defines reusable methods that can be called from `match:`, `data:`, or other utils.

```yaml
utils:
  get_title:
    parameters:
      - tech_asset
    do:
      - return: "<b>My Rule</b> risk at <b>{tech_asset.title}</b>"

  get_impact:
    parameters:
      - tech_asset
    do:
      - assign:
          - impact: low
      - if:
          # ... condition ...
          then:
            - assign:
                impact: medium
      - return: "{impact}"
```

## Variable References

Variables are referenced using curly braces `{...}` inside strings. The engine supports several reference prefixes:

| Syntax | Description | Example |
|--------|-------------|---------|
| `{varname}` | Local variable | `{impact}` |
| `{varname.field}` | Nested field access | `{tech_asset.id}` |
| `{$model.path}` | Access the threat model | `{$model.data_assets.my_asset.confidentiality}` |
| `{$risk.field}` | Access the risk category | `{$risk.id}` |
| `{.field}` | Access current loop item | `{.attributes.sourcecode-repository}` |

Nested path resolution is supported: `{$model.data_assets.{data_id}.{type}}` resolves `data_id` and `type` first, then navigates the model.

## Statements

Statements are the executable building blocks of the script. They appear inside `do:` blocks.

### `assign`

Assigns values to variables.

```yaml
- assign:
    - impact: low
    - highest_confidentiality: "get_highest({tech_asset}, confidentiality)"
```

Each item in the list is a single key-value pair. The value can be a literal or an expression.

### `return`

Returns a value from the current method and stops execution.

```yaml
- return: true
- return: "{impact}"
- return: "<b>Some Title</b> risk at <b>{tech_asset.title}</b>"
```

### `if`

Conditional execution. Requires a boolean expression and a `then:` block. Optionally supports `else:`.

```yaml
- if:
    contains:
      item: git
      in: "{tech_asset.tags}"
    then:
      - return: "Git detected"
    else:
      - return: "No git"
```

The condition can be any boolean expression (see [Expressions](#expressions)).

### `loop`

Iterates over a collection.

```yaml
- loop:
    in: "{tech_asset.data_assets_processed}"
    item: data_id
    do:
      - if:
          greater:
            first: "{$model.data_assets.{data_id}.{type}}"
            second: "{value}"
            as: "{type}"
          then:
            - assign:
                value: "{$model.data_assets.{data_id}.{type}}"
```

| Key | Description |
|-----|-------------|
| `in` | The collection to iterate over |
| `item` | Variable name for the current element |
| `index` | (Optional) Variable name for the current index |
| `do` | Statements to execute per iteration |

### `defer`

Registers statements to execute when the current method exits, regardless of the return path. Useful for explanation tracking.

```yaml
- defer:
    - explain: "the highest {type} value is '{value}'"
```

### `explain`

Adds explanation text to the execution trace. Explanations are collected and included in the risk's `risk_explanation` and `rating_explanation` fields.

```yaml
- explain: "{type} value of the technical asset is '{value}'"
```

## Expressions

Expressions evaluate to values and are used inside statements and data templates.

### Boolean Expressions

#### `true` / `false`

Tests if an expression evaluates to the given boolean.

```yaml
true: "{tech_asset.out_of_scope}"    # true if value is truthy
false: "{tech_asset.out_of_scope}"   # true if value is falsy
```

#### `and`

All sub-expressions must be true (short-circuits on first false).

```yaml
and:
  - false: "{tech_asset.out_of_scope}"
  - true: "{tech_asset.technologies.has_secrets}"
```

#### `or`

At least one sub-expression must be true (short-circuits on first true).

```yaml
or:
  - equal-or-greater:
      as: confidentiality
      first: "{highest_confidentiality}"
      second: confidential
  - equal-or-greater:
      as: integrity
      first: "{highest_integrity}"
      second: critical
```

### Comparison Expressions

All comparison expressions take `first`, `second`, and optionally `as` (cast type for ordered comparison).

#### `equal`

```yaml
equal:
  first: "{value}"
  second: "some-string"
```

#### `not-equal`

```yaml
not-equal:
  first: "{value}"
  second: "some-string"
```

#### `greater`

```yaml
greater:
  first: "{$model.data_assets.{data_id}.confidentiality}"
  second: "{value}"
  as: confidentiality
```

#### `less`

```yaml
less:
  first: "{value}"
  second: critical
  as: criticality
```

#### `equal-or-greater`

```yaml
equal-or-greater:
  as: confidentiality
  first: "{highest_confidentiality}"
  second: confidential
```

#### `equal-or-less`

```yaml
equal-or-less:
  as: impact
  first: "{current_impact}"
  second: medium
```

### Cast Types (`as`)

The `as` parameter in comparisons converts string enum values to numeric ordinals for ordered comparison. Supported types:

| Cast Type | Values (low to high) |
|-----------|---------------------|
| `authentication` | Authentication enum values |
| `authorization` | Authorization enum values |
| `confidentiality` | `public` < `internal` < `restricted` < `confidential` < `strictly-confidential` |
| `criticality` | `archive` < `operational` < `important` < `critical` < `mission-critical` |
| `integrity` | Same as criticality |
| `availability` | Same as criticality |
| `probability` | `improbable` < `possible` < `probable` |
| `encryption` | Encryption style enum values |
| `quantity` | Quantity enum values |
| `impact` | `low` < `medium` < `high` < `very-high` |
| `likelihood` | `unlikely` < `likely` < `very-likely` < `frequent` |
| `size` | Technical asset size enum values |

### Collection Expressions

#### `any`

Returns true if any item in the collection matches the condition.

```yaml
any:
  in: "{tech_asset.technologies}"
  or:
    - true: "{.attributes.sourcecode-repository}"
    - true: "{.attributes.artifact-registry}"
```

- `in`: The collection to search.
- The condition can be `and`, `or`, or any boolean expression.
- Use `.` prefix to reference fields of the current item.

#### `all`

Returns true only if all items in the collection match the condition.

```yaml
all:
  in: "{tech_asset.communication_links}"
  and:
    - true: "{.encrypted}"
```

#### `count`

Returns the number of items matching a condition.

```yaml
count:
  in: "{tech_asset.data_assets_processed}"
  # optional condition
```

#### `contains`

Checks if an item exists in a collection.

```yaml
contains:
  item: git
  in: "{tech_asset.tags}"
```

Optionally supports `as` for typed comparison.

### Method Calls

Call utility methods or built-in functions from within string expressions:

```yaml
title: "get_title({tech_asset})"
severity: "calculate_severity(unlikely, get_impact({tech_asset}))"
```

Arguments are comma-separated inside parentheses. Arguments can be:
- Variable references: `{tech_asset}`
- Literal strings: `unlikely`
- Nested method calls: `get_impact({tech_asset})`

## Built-in Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `calculate_severity(likelihood, impact)` | likelihood (string/enum), impact (string/enum) | Calculates risk severity from likelihood and impact |

## Model Data Access

The threat model is accessible via `{$model.path}`. Common paths:

| Path | Description |
|------|-------------|
| `$model.technical_assets` | Map of all technical assets |
| `$model.data_assets` | Map of all data assets |
| `$model.data_assets.{id}.confidentiality` | Confidentiality of a data asset |
| `$model.data_assets.{id}.integrity` | Integrity of a data asset |
| `$model.data_assets.{id}.availability` | Availability of a data asset |

### Technical Asset Properties

When iterating over technical assets (the parameter passed to `match:`, `data:`, etc.), common properties include:

| Property | Type | Description |
|----------|------|-------------|
| `id` | string | Technical asset identifier |
| `title` | string | Display title |
| `out_of_scope` | bool | Whether the asset is out of scope |
| `technologies` | array | List of technology objects with `.attributes` |
| `tags` | array | List of string tags |
| `data_assets_processed` | array | IDs of data assets processed |
| `data_assets_stored` | array | IDs of data assets stored |
| `confidentiality` | string | Asset's own confidentiality rating |
| `integrity` | string | Asset's own integrity rating |
| `availability` | string | Asset's own availability rating |
| `communication_links` | array | Communication links from this asset |
