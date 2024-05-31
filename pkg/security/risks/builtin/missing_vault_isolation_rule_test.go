package builtin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestMissingVaultIsolationRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewMissingVaultIsolationRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingVaultIsolationRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewMissingVaultIsolationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: true,
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

func TestMissingVaultIsolationRuleGenerateRisksNoVaultNoRisksCreated(t *testing.T) {
	rule := NewMissingVaultIsolationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "no-vault",
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

func TestMissingVaultIsolationRuleGenerateRisksTwoVaultsNoRisksCreated(t *testing.T) {
	rule := NewMissingVaultIsolationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "First Vault",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.Vault: true,
						},
					},
				},
			},
			"ta2": {
				Title:      "Second Vault",
				OutOfScope: false,
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

func TestMissingVaultIsolationRuleGenerateRisksVaultAndStorageNoRisksCreated(t *testing.T) {
	rule := NewMissingVaultIsolationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Vault",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.Vault: true,
						},
					},
				},
			},
			"ta2": {
				Id:         "ta2",
				Title:      "Vault Datastore",
				OutOfScope: false,
				Type:       types.Datastore,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					TargetId: "ta1",
					SourceId: "ta2",
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingVaultIsolationRuleGenerateRisksDifferentTrustBoundariesNoRisksCreated(t *testing.T) {
	rule := NewMissingVaultIsolationRule()
	tb1 := &types.TrustBoundary{
		Id:                    "tb1",
		Title:                 "First Trust Boundary",
		TechnicalAssetsInside: []string{"ta1"},
		Type:                  types.NetworkCloudProvider,
	}
	tb2 := &types.TrustBoundary{
		Id:                    "tb2",
		Title:                 "Second Trust Boundary",
		TechnicalAssetsInside: []string{"ta1"},
		Type:                  types.NetworkCloudProvider,
	}
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Vault",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.Vault: true,
						},
					},
				},
			},
			"ta2": {
				Id:         "ta2",
				Title:      "Vault Consumer",
				OutOfScope: false,
				Type:       types.Process,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					TargetId: "ta1",
					SourceId: "ta2",
				},
			},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": tb1,
			"tb2": tb2,
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"ta1": tb1,
			"ta2": tb2,
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type MissingVaultIsolationRuleTest struct {
	confidentiality types.Confidentiality
	integrity       types.Criticality
	availability    types.Criticality
	tbType          types.TrustBoundaryType

	expectedImpact     types.RiskExploitationImpact
	expectedLikelihood types.RiskExploitationLikelihood
	expectedMessage    string
}

func TestMissingVaultIsolationRuleGenerateRisksRiskCreated(t *testing.T) {
	testCases := map[string]MissingVaultIsolationRuleTest{
		"medium impact": {
			confidentiality:    types.Confidential,
			integrity:          types.Critical,
			availability:       types.Critical,
			tbType:             types.NetworkCloudProvider,
			expectedImpact:     types.MediumImpact,
			expectedLikelihood: types.Unlikely,
			expectedMessage:    "network segment",
		},
		"strictly confidential high impact": {
			confidentiality:    types.StrictlyConfidential,
			integrity:          types.Critical,
			availability:       types.Critical,
			tbType:             types.NetworkCloudProvider,
			expectedImpact:     types.HighImpact,
			expectedLikelihood: types.Unlikely,
			expectedMessage:    "network segment",
		},
		"mission critical integrity high impact": {
			confidentiality:    types.Confidential,
			integrity:          types.MissionCritical,
			availability:       types.Critical,
			tbType:             types.NetworkCloudProvider,
			expectedImpact:     types.HighImpact,
			expectedLikelihood: types.Unlikely,
			expectedMessage:    "network segment",
		},
		"mission critical availability high impact": {
			confidentiality:    types.Confidential,
			integrity:          types.Critical,
			availability:       types.MissionCritical,
			tbType:             types.NetworkCloudProvider,
			expectedImpact:     types.HighImpact,
			expectedLikelihood: types.Unlikely,
			expectedMessage:    "network segment",
		},
		"same execution environment": {
			confidentiality:    types.Confidential,
			integrity:          types.Critical,
			availability:       types.Critical,
			tbType:             types.ExecutionEnvironment,
			expectedImpact:     types.MediumImpact,
			expectedLikelihood: types.Likely,
			expectedMessage:    "execution environment",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingVaultIsolationRule()

			tb1 := &types.TrustBoundary{
				Id:                    "tb1",
				Title:                 "First Trust Boundary",
				TechnicalAssetsInside: []string{"ta1", "ta2"},
				Type:                  testCase.tbType,
			}
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:         "ta1",
						Title:      "Vault",
						OutOfScope: false,
						Technologies: types.TechnologyList{
							{
								Name: "service-registry",
								Attributes: map[string]bool{
									types.Vault: true,
								},
							},
						},
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
					},
					"ta2": {
						Id:         "ta2",
						Title:      "Vault Consumer",
						OutOfScope: false,
						Type:       types.Process,
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"ta1": {
						{
							TargetId: "ta1",
							SourceId: "ta2",
						},
					},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{
					"tb1": tb1,
				},
				DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
					"ta1": tb1,
					"ta2": tb1,
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, testCase.expectedLikelihood, risks[0].ExploitationLikelihood)

			expTitle := fmt.Sprintf("<b>Missing Vault Isolation</b> to further encapsulate and protect vault-related asset <b>Vault</b> against unrelated "+
				"lower protected assets <b>in the same %s</b>, which might be easier to compromise by attackers", testCase.expectedMessage)
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}
