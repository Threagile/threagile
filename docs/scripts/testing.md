# Testing Risk Rule Scripts

Threagile provides two ways to test your YAML risk rule scripts: the `cmd/script` CLI tool for interactive development, and Go unit tests for automated verification.

## Interactive Testing with `cmd/script`

The `cmd/script` tool parses a risk rule script, runs it against a model file, and prints the generated risks with their explanations. This is the fastest way to iterate while developing a new rule.

### Running the Tool

```bash
# Run with the default script (accidental-secret-leak.yaml)
go run cmd/script/main.go

# Run with a custom script
go run cmd/script/main.go -script path/to/your-rule.yaml
```

### How It Works

The tool performs these steps:

1. **Reads the script file** specified by `-script` (defaults to `pkg/risks/scripts/accidental-secret-leak.yaml`)
2. **Reads the model file** from `test/parsed-model.yaml`
3. **Parses** both files
4. **Generates risks** by running the script against the model
5. **Prints** each generated risk with:
   - Risk explanation (why the risk was flagged)
   - Rating explanation (how severity was determined)
   - Full risk data as YAML
   - Matched technical assets

### Example Output

```
Risk 'Accidental Secret Leak' has been flagged for technical asset 'git-repo' because
  technical asset is not out of scope, and
  technology has attribute 'sourcecode-repository'

'Severity' is 'medium' because
  confidentiality value of the technical asset is 'public',
  confidentiality value of data asset 'source-code' is 'confidential'

generated risk #1 for "accidental-secret-leak":
category_id: accidental-secret-leak
synthetic_id: accidental-secret-leak@git-repo
title: <b>Accidental Secret Leak (Git)</b> risk at <b>Git Repository</b>: <u>Git Leak Prevention</u>
severity: medium
exploitation_likelihood: unlikely
exploitation_impact: medium
...

found 1 asset(s) for risk #1 "accidental-secret-leak@git-repo"
  - Git Repository
```

### Test Model

The tool reads its model from `test/parsed-model.yaml`. This is a full Threagile model file containing technical assets, data assets, trust boundaries, and communication links.

To test your rule against different scenarios, you can either:
- Modify `test/parsed-model.yaml` to include assets that match your rule
- Create a separate model file and update the tool's source to point to it

### Debugging Tips

- If no risks are generated, the `match:` condition is not returning `true` for any asset. Check that the model contains assets with the expected properties.
- If parsing fails, the error message includes the problematic script fragment with line numbers.
- Add `explain` statements to trace variable values during execution.
- Use `defer` with `explain` to see final variable values after method execution.

## Unit Testing with Go

For automated testing, write Go tests that load the script and run it against programmatically constructed models. This lets you test specific scenarios without maintaining separate model files.

### Test Structure

```go
package scripts

import (
    _ "embed"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/threagile/threagile/pkg/risks/script"
    "github.com/threagile/threagile/pkg/types"
)

//go:embed my-custom-rule.yaml
var myCustomRule string

func loadMyCustomRule() types.RiskRule {
    result := new(script.RiskRule).Init()
    riskRule, _ := result.ParseFromData([]byte(myCustomRule))
    return riskRule
}
```

The `//go:embed` directive embeds the YAML file at compile time, so the test file must be in the same package directory as the YAML script (or use a relative path from the package).

### Writing Test Cases

**Test that out-of-scope assets are skipped:**

```go
func TestMyRuleOutOfScopeNoRisks(t *testing.T) {
    rule := loadMyCustomRule()

    risks, err := rule.GenerateRisks(&types.Model{
        TechnicalAssets: map[string]*types.TechnicalAsset{
            "ta1": {
                OutOfScope: true,
            },
        },
    })

    assert.Nil(t, err)
    assert.Empty(t, risks)
}
```

**Test that assets without matching technology are skipped:**

```go
func TestMyRuleWrongTechnologyNoRisks(t *testing.T) {
    rule := loadMyCustomRule()

    risks, err := rule.GenerateRisks(&types.Model{
        TechnicalAssets: map[string]*types.TechnicalAsset{
            "ta1": {
                Technologies: types.TechnologyList{
                    {
                        Name: "tool",
                        Attributes: map[string]bool{
                            "web-application": false,
                        },
                    },
                },
            },
        },
    })

    assert.Nil(t, err)
    assert.Empty(t, risks)
}
```

**Test that matching assets generate a risk:**

```go
func TestMyRuleMatchingAssetCreatesRisk(t *testing.T) {
    rule := loadMyCustomRule()

    risks, err := rule.GenerateRisks(&types.Model{
        TechnicalAssets: map[string]*types.TechnicalAsset{
            "ta1": {
                Title: "My App",
                Technologies: types.TechnologyList{
                    {
                        Name: "web-application",
                        Attributes: map[string]bool{
                            "web-application": true,
                        },
                    },
                },
            },
        },
    })

    assert.Nil(t, err)
    assert.Equal(t, 1, len(risks))
    assert.Contains(t, risks[0].Title, "My App")
}
```

**Test impact escalation based on data assets:**

```go
func TestMyRuleHighConfidentialityHighImpact(t *testing.T) {
    rule := loadMyCustomRule()

    risks, err := rule.GenerateRisks(&types.Model{
        TechnicalAssets: map[string]*types.TechnicalAsset{
            "ta1": {
                Technologies: types.TechnologyList{
                    {
                        Name: "web-application",
                        Attributes: map[string]bool{
                            "web-application": true,
                        },
                    },
                },
                DataAssetsProcessed: []string{"sensitive-data"},
            },
        },
        DataAssets: map[string]*types.DataAsset{
            "sensitive-data": {
                Confidentiality: types.StrictlyConfidential,
            },
        },
    })

    assert.Nil(t, err)
    assert.Equal(t, 1, len(risks))
    assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}
```

### Running Tests

```bash
# Run all script tests
go test ./pkg/risks/scripts/...

# Run a specific test
go test ./pkg/risks/scripts/... -run TestMyRule

# Run with verbose output
go test -v ./pkg/risks/scripts/...
```

### File Organization

Place your script and test files together in `pkg/risks/scripts/`:

```
pkg/risks/scripts/
├── accidental-secret-leak.yaml           # script
├── accidental_secret_leak_test.go        # tests for the script
├── my-custom-rule.yaml                   # your new script
└── my_custom_rule_test.go                # your new tests
```

The test file must use `//go:embed` to reference the YAML file, so both files must be in the same directory.

## Testing Workflow

A recommended workflow for developing a new risk rule:

1. **Start with the YAML script** — define metadata and a basic `match:` condition.
2. **Use `cmd/script`** to iterate quickly — modify the script, re-run, and inspect output.
3. **Add `explain` statements** to debug variable values and decision paths.
4. **Write Go unit tests** covering:
   - Out-of-scope assets are skipped
   - Assets without matching criteria are skipped
   - Assets with matching criteria generate risks
   - Impact/severity escalation based on data asset classification
   - Edge cases specific to your rule
5. **Run the full test suite** to verify no regressions: `go test ./...`
