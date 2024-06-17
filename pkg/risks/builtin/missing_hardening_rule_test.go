package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestMissingHardeningRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewMissingHardeningRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingHardeningRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewMissingHardeningRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: true,
				RAA:        100,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type MissingHardeningRuleNoRisksTest struct {
	raa                int
	technicalAssetType types.TechnicalAssetType
	enabledAttribute   string
}

func TestMissingHardeningRuleNoRisksCreated(t *testing.T) {
	testCases := map[string]MissingHardeningRuleNoRisksTest{
		"raa less limit for data store": {
			raa:                39,
			technicalAssetType: types.Datastore,
			enabledAttribute:   types.IsDevelopmentRelevant,
		},
		"raa less limit for high value target": {
			raa:                39,
			technicalAssetType: types.Process,
			enabledAttribute:   types.IsHighValueTarget,
		},
		"raa less reduced limit for not data store or high value target": {
			raa:                54,
			technicalAssetType: types.Process,
			enabledAttribute:   "any other",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingHardeningRule()
			input := &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:    "ta1",
						Title: "Test Technical Asset",
						Type:  testCase.technicalAssetType,
						Technologies: types.TechnologyList{
							{
								Name:       "some-technology",
								Attributes: map[string]bool{},
							},
						},
					},
				},
			}
			input.TechnicalAssets["ta1"].RAA = float64(testCase.raa)
			input.TechnicalAssets["ta1"].Technologies[0].Attributes[testCase.enabledAttribute] = true
			risks, err := rule.GenerateRisks(input)

			assert.Nil(t, err)
			assert.Empty(t, risks)
		})
	}
}

type MissingHardeningRuleRisksCreatedTest struct {
	raa                int
	technicalAssetType types.TechnicalAssetType
	enabledAttribute   string
	confidentiality    types.Confidentiality
	integrity          types.Criticality

	expectedImpact types.RiskExploitationImpact
}

func TestMissingHardeningRuleRisksCreated(t *testing.T) {
	testCases := map[string]MissingHardeningRuleRisksCreatedTest{
		"raa higher reduced limit for data store": {
			raa:                40,
			technicalAssetType: types.Datastore,
			enabledAttribute:   types.IsDevelopmentRelevant,
			expectedImpact:     types.LowImpact,
		},
		"raa higher reduced limit for high value target": {
			raa:                40,
			technicalAssetType: types.Process,
			enabledAttribute:   types.IsHighValueTarget,
			expectedImpact:     types.LowImpact,
		},
		"raa higher limit for not high value target or data store": {
			raa:                55,
			technicalAssetType: types.Process,
			enabledAttribute:   types.IsDevelopmentRelevant,
			expectedImpact:     types.LowImpact,
		},
		"process strictly confidential data": {
			raa:                55,
			technicalAssetType: types.Datastore,
			enabledAttribute:   types.IsHighValueTarget,
			confidentiality:    types.StrictlyConfidential,
			integrity:          types.Critical,
			expectedImpact:     types.MediumImpact,
		},
		"process mission critical integrity data": {
			raa:                55,
			technicalAssetType: types.Datastore,
			enabledAttribute:   types.IsHighValueTarget,
			confidentiality:    types.Confidential,
			integrity:          types.MissionCritical,
			expectedImpact:     types.MediumImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingHardeningRule()
			input := &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:    "ta1",
						Title: "Test Technical Asset",
						Type:  types.Datastore,
						Technologies: types.TechnologyList{
							{
								Name:       "some-technology",
								Attributes: map[string]bool{},
							},
						},
						DataAssetsProcessed: []string{"da1"},
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"da1": {
						Title:           "Test Data Asset",
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
					},
				},
			}
			input.TechnicalAssets["ta1"].RAA = float64(testCase.raa)
			tech := input.TechnicalAssets["ta1"].Technologies[0]
			tech.Attributes[testCase.enabledAttribute] = true
			risks, err := rule.GenerateRisks(input)

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, "<b>Missing Hardening</b> risk at <b>Test Technical Asset</b>", risks[0].Title)
		})
	}
}
