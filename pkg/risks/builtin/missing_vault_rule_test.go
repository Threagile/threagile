package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestMissingVaultRuleGenerateRisksEmptyModelRiskCreated(t *testing.T) {
	rule := NewMissingVaultRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Missing Vault (Secret Storage)</b> in the threat model", risks[0].Title)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)

}

func TestMissingVaultRuleGenerateRisksHasVaultNoRisksCreated(t *testing.T) {
	rule := NewMissingVaultRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "Vault",
				Technologies: types.TechnologyList{
					{
						Name: "vault",
						Attributes: map[string]bool{
							types.Vault: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type MissingVaultRuleTest struct {
	confidentiality types.Confidentiality
	integrity       types.Criticality
	availability    types.Criticality

	expectedImpact types.RiskExploitationImpact
}

func TestMissingVaultRuleGenerateRisksRiskCreated(t *testing.T) {
	testCases := map[string]MissingVaultRuleTest{
		"low impact": {
			confidentiality: types.Restricted,
			integrity:       types.Important,
			availability:    types.Important,
			expectedImpact:  types.LowImpact,
		},
		"confidential data processed medium impact": {
			confidentiality: types.Confidential,
			integrity:       types.Important,
			availability:    types.Important,
			expectedImpact:  types.MediumImpact,
		},
		"critical integrity data processed medium impact": {
			confidentiality: types.Restricted,
			integrity:       types.Critical,
			availability:    types.Important,
			expectedImpact:  types.MediumImpact,
		},
		"critical availability data processed medium impact": {
			confidentiality: types.Restricted,
			integrity:       types.Important,
			availability:    types.Critical,
			expectedImpact:  types.MediumImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingVaultRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Title:           "Test Technical Asset",
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
						Technologies: types.TechnologyList{
							{
								Name: "vault",
								Attributes: map[string]bool{
									types.Vault: false,
								},
							},
						},
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, "<b>Missing Vault (Secret Storage)</b> in the threat model (referencing asset <b>Test Technical Asset</b> as an example)", risks[0].Title)
		})
	}
}

func TestMissingVaultRuleGenerateRisksRiskCreatedWithMoreSensitiveAsset(t *testing.T) {
	rule := NewMissingVaultRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:           "Test Technical Asset",
				Confidentiality: types.Restricted,
				Integrity:       types.Important,
				Availability:    types.Important,
				Technologies: types.TechnologyList{
					{
						Name: "vault",
						Attributes: map[string]bool{
							types.Vault: false,
						},
					},
				},
			},
			"ta2": {
				Title:           "More Relevant Technical Asset",
				Confidentiality: types.Confidential,
				Integrity:       types.Important,
				Availability:    types.Important,
				Technologies: types.TechnologyList{
					{
						Name: "vault",
						Attributes: map[string]bool{
							types.Vault: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing Vault (Secret Storage)</b> in the threat model (referencing asset <b>More Relevant Technical Asset</b> as an example)", risks[0].Title)
}

func TestMissingVaultRuleGenerateRisksRestrictedConfidentialityLowImpact(t *testing.T) {
	rule := NewMissingVaultRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:              "ta1",
				Title:           "Test Technical Asset",
				Confidentiality: types.Restricted,
				Integrity:       types.Important,
				Availability:    types.Important,
				Technologies: types.TechnologyList{
					{
						Name: "some-tech",
						Attributes: map[string]bool{
							types.Vault: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}

func TestMissingVaultRuleGenerateRisksVaultPresentWithOtherSensitiveAssetsNoRiskCreated(t *testing.T) {
	rule := NewMissingVaultRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta-vault": {
				Id:    "ta-vault",
				Title: "Vault Asset",
				Technologies: types.TechnologyList{
					{
						Name: "vault",
						Attributes: map[string]bool{
							types.Vault: true,
						},
					},
				},
			},
			"ta-sensitive": {
				Id:              "ta-sensitive",
				Title:           "Sensitive Asset",
				Confidentiality: types.StrictlyConfidential,
				Integrity:       types.MissionCritical,
				Availability:    types.MissionCritical,
				Technologies: types.TechnologyList{
					{
						Name: "some-tech",
						Attributes: map[string]bool{
							types.Vault: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingVaultRuleGenerateRisksTwoAssetsWithSameSensitivityDeterministicSelection(t *testing.T) {
	rule := NewMissingVaultRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"asset-aaa": {
				Id:              "asset-aaa",
				Title:           "Asset AAA",
				Confidentiality: types.Confidential,
				Integrity:       types.Important,
				Availability:    types.Important,
				Technologies: types.TechnologyList{
					{
						Name: "some-tech",
						Attributes: map[string]bool{
							types.Vault: false,
						},
					},
				},
			},
			"asset-zzz": {
				Id:              "asset-zzz",
				Title:           "Asset ZZZ",
				Confidentiality: types.Confidential,
				Integrity:       types.Important,
				Availability:    types.Important,
				Technologies: types.TechnologyList{
					{
						Name: "some-tech",
						Attributes: map[string]bool{
							types.Vault: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	// The rule iterates in sorted ID order, so the last asset encountered with the same score wins.
	// Both have identical sensitivity scores; the sorted iteration ensures deterministic behavior.
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestMissingVaultRuleGenerateRisksSingleAssetWithVaultTechnologyNoRiskCreated(t *testing.T) {
	rule := NewMissingVaultRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Vault Asset",
				Technologies: types.TechnologyList{
					{
						Name: "vault",
						Attributes: map[string]bool{
							types.Vault: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}
