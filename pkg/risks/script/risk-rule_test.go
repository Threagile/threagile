package script

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

const minimalTestYAML = `
id: test-rule
title: Test Rule
function: operations
stride: information-disclosure
cwe: 200
description: Test description
impact: Test impact
asvs: V1
cheat_sheet: https://example.com
action: Test Action
mitigation: Test mitigation
check: Is it mitigated?
detection_logic: Always
risk_assessment: Low
false_positives: None

risk:
  id:
    parameter: tech_asset
    id: "{$risk.id}@{tech_asset.id}"
  match:
    parameter: tech_asset
    do:
      - if:
          false: "{tech_asset.out_of_scope}"
          then:
            return: true
  data:
    parameter: tech_asset
    title: "<b>Test Rule</b> risk at <b>{tech_asset.title}</b>"
    severity: "calculate_severity(unlikely, low)"
    exploitation_likelihood: unlikely
    exploitation_impact: low
    data_breach_probability: probable
    data_breach_technical_assets:
      - "{tech_asset.id}"
    most_relevant_technical_asset: "{tech_asset.id}"
`

func TestRiskRule_ParseFromData_MinimalValid(t *testing.T) {
	rule := new(RiskRule).Init()
	_, err := rule.ParseFromData([]byte(minimalTestYAML))
	assert.NoError(t, err)
	assert.NotNil(t, rule.script)
}

func TestRiskRule_Category_ReturnsCorrectValues(t *testing.T) {
	rule := new(RiskRule).Init()
	_, err := rule.ParseFromData([]byte(minimalTestYAML))
	assert.NoError(t, err)

	cat := rule.Category()
	assert.NotNil(t, cat)
	assert.Equal(t, "test-rule", cat.ID)
	assert.Equal(t, "Test Rule", cat.Title)
	assert.Equal(t, "Test description", cat.Description)
	assert.Equal(t, "Test impact", cat.Impact)
	assert.Equal(t, "V1", cat.ASVS)
	assert.Equal(t, "https://example.com", cat.CheatSheet)
	assert.Equal(t, "Test Action", cat.Action)
	assert.Equal(t, "Test mitigation", cat.Mitigation)
	assert.Equal(t, "Is it mitigated?", cat.Check)
	assert.Equal(t, "Always", cat.DetectionLogic)
	assert.Equal(t, "Low", cat.RiskAssessment)
	assert.Equal(t, "None", cat.FalsePositives)
	assert.Equal(t, 200, cat.CWE)
}

func TestRiskRule_SupportedTags_Empty(t *testing.T) {
	rule := new(RiskRule).Init()
	_, err := rule.ParseFromData([]byte(minimalTestYAML))
	assert.NoError(t, err)

	tags := rule.SupportedTags()
	assert.Empty(t, tags)
}

func TestRiskRule_SupportedTags_WithTags(t *testing.T) {
	yamlWithTags := minimalTestYAML + `
supported-tags:
  - aws
  - cloud
`
	rule := new(RiskRule).Init()
	_, err := rule.ParseFromData([]byte(yamlWithTags))
	assert.NoError(t, err)

	tags := rule.SupportedTags()
	assert.Len(t, tags, 2)
	assert.Contains(t, tags, "aws")
	assert.Contains(t, tags, "cloud")
}

func TestRiskRule_GenerateRisks_MatchingModel(t *testing.T) {
	rule := new(RiskRule).Init()
	_, err := rule.ParseFromData([]byte(minimalTestYAML))
	assert.NoError(t, err)

	model := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Test Asset",
			},
		},
	}

	risks, riskErr := rule.GenerateRisks(model)
	assert.NoError(t, riskErr)
	assert.NotEmpty(t, risks)

	assert.Equal(t, "test-rule", risks[0].CategoryId)
	assert.Contains(t, risks[0].SyntheticId, "ta1")
	assert.Equal(t, "ta1", risks[0].MostRelevantTechnicalAssetId)
	assert.Contains(t, risks[0].DataBreachTechnicalAssetIDs, "ta1")
}

func TestRiskRule_GenerateRisks_EmptyModel(t *testing.T) {
	rule := new(RiskRule).Init()
	_, err := rule.ParseFromData([]byte(minimalTestYAML))
	assert.NoError(t, err)

	model := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{},
	}

	_, riskErr := rule.GenerateRisks(model)
	// Empty technical assets map serializes without a "technical_assets" key,
	// so the script reports "no technical assets in scope"
	assert.Error(t, riskErr)
	assert.Contains(t, riskErr.Error(), "no technical assets in scope")
}

func TestRiskRule_GenerateRisks_OutOfScopeAssetSkipped(t *testing.T) {
	rule := new(RiskRule).Init()
	_, err := rule.ParseFromData([]byte(minimalTestYAML))
	assert.NoError(t, err)

	model := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Out of Scope Asset",
				OutOfScope: true,
			},
		},
	}

	risks, riskErr := rule.GenerateRisks(model)
	assert.NoError(t, riskErr)
	assert.Empty(t, risks)
}

func TestRiskRule_GenerateRisks_NilScript(t *testing.T) {
	rule := new(RiskRule).Init()
	// Do not parse, so script is nil

	model := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Test Asset",
			},
		},
	}

	_, riskErr := rule.GenerateRisks(model)
	assert.Error(t, riskErr)
	assert.Contains(t, riskErr.Error(), "no script found")
}

func TestRiskRule_ParseFromData_InvalidYAML(t *testing.T) {
	invalidYAML := []byte(`{invalid yaml: [`)

	rule := new(RiskRule).Init()
	_, err := rule.ParseFromData(invalidYAML)
	assert.Error(t, err)
}

func TestRiskRule_ParseFromData_NoRiskSection(t *testing.T) {
	yamlNoRisk := []byte(`
id: test-rule
title: Test Rule
`)
	rule := new(RiskRule).Init()
	_, err := rule.ParseFromData(yamlNoRisk)
	// No risk section means script is nil (no risk map to parse)
	assert.NoError(t, err)
}

func TestRiskRule_GenerateRisks_MultipleAssets(t *testing.T) {
	rule := new(RiskRule).Init()
	_, err := rule.ParseFromData([]byte(minimalTestYAML))
	assert.NoError(t, err)

	model := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Asset One",
			},
			"ta2": {
				Id:    "ta2",
				Title: "Asset Two",
			},
		},
	}

	risks, riskErr := rule.GenerateRisks(model)
	assert.NoError(t, riskErr)
	assert.Len(t, risks, 2)

	syntheticIDs := make([]string, len(risks))
	for i, r := range risks {
		syntheticIDs[i] = r.SyntheticId
	}
	assert.Contains(t, syntheticIDs, "test-rule@ta1")
	assert.Contains(t, syntheticIDs, "test-rule@ta2")
}

func TestRiskRule_GenerateRisks_MixedScopeAssets(t *testing.T) {
	rule := new(RiskRule).Init()
	_, err := rule.ParseFromData([]byte(minimalTestYAML))
	assert.NoError(t, err)

	model := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "In Scope",
			},
			"ta2": {
				Id:         "ta2",
				Title:      "Out of Scope",
				OutOfScope: true,
			},
		},
	}

	risks, riskErr := rule.GenerateRisks(model)
	assert.NoError(t, riskErr)
	assert.Len(t, risks, 1)
	assert.Equal(t, "test-rule@ta1", risks[0].SyntheticId)
}

func TestRiskRule_ImplementsRiskRuleInterface(t *testing.T) {
	rule := new(RiskRule).Init()
	_, err := rule.ParseFromData([]byte(minimalTestYAML))
	assert.NoError(t, err)

	// Verify RiskRule satisfies the types.RiskRule interface at compile time
	var _ types.RiskRule = rule
}
