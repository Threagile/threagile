package builtin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestMissingIdentityProviderIsolationRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewMissingIdentityProviderIsolationRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingIdentityProviderIsolationRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewMissingIdentityProviderIsolationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: true,
				Technologies: types.TechnologyList{
					{
						Name: "some-technology",
						Attributes: map[string]bool{
							types.IsIdentityRelated: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingIdentityProviderIsolationRuleGenerateRisksNotIdentityRelatedNoRisksCreated(t *testing.T) {
	rule := NewMissingIdentityProviderIsolationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "some-technology",
						Attributes: map[string]bool{
							types.IsIdentityRelated: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingIdentityProviderIsolationRuleGenerateRisksSparringAssetIsIdentityRelatedRelatedNoRisksCreated(t *testing.T) {
	rule := NewMissingIdentityProviderIsolationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "some-technology",
						Attributes: map[string]bool{
							types.IsIdentityRelated: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Test Sparring Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "some-technology",
						Attributes: map[string]bool{
							types.IsIdentityRelated: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingIdentityProviderIsolationRuleGenerateRisksSparringAssetIsCloseToHighValueTargetsToleratedNoRisksCreated(t *testing.T) {
	rule := NewMissingIdentityProviderIsolationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "some-technology",
						Attributes: map[string]bool{
							types.IsIdentityRelated: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Test Sparring Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "some-technology",
						Attributes: map[string]bool{
							types.IsCloseToHighValueTargetsTolerated: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingIdentityProviderIsolationRuleGenerateRisksSparringAssetNotInTheSameTrustBoundaryOrExecutionEnvironmentNoRisksCreated(t *testing.T) {
	rule := NewMissingIdentityProviderIsolationRule()
	tb1 := &types.TrustBoundary{
		Id: "tb1",
	}
	tb2 := &types.TrustBoundary{
		Id: "tb2",
	}
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "some-technology",
						Attributes: map[string]bool{
							types.IsIdentityRelated: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Test Sparring Technical Asset",
			},
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"ta1": tb1,
			"ta2": tb2,
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type MissingIdentityProviderIsolationRuleTest struct {
	confidentiality types.Confidentiality
	integrity       types.Criticality
	availability    types.Criticality
	tbType          types.TrustBoundaryType

	expectedImpact               types.RiskExploitationImpact
	expectedLikelihood           types.RiskExploitationLikelihood
	expectedTrustBoundaryMessage string
}

func TestMissingIdentityProviderIsolationRule(t *testing.T) {
	testCases := map[string]MissingIdentityProviderIsolationRuleTest{
		"same execution environment": {
			confidentiality:              types.Confidential,
			integrity:                    types.Critical,
			availability:                 types.Critical,
			tbType:                       types.ExecutionEnvironment,
			expectedImpact:               types.HighImpact,
			expectedLikelihood:           types.Likely,
			expectedTrustBoundaryMessage: "execution environment",
		},
		"more impact for strictly confidential asset": {
			confidentiality:              types.StrictlyConfidential,
			integrity:                    types.Critical,
			availability:                 types.Critical,
			tbType:                       types.ExecutionEnvironment,
			expectedImpact:               types.VeryHighImpact,
			expectedLikelihood:           types.Likely,
			expectedTrustBoundaryMessage: "execution environment",
		},
		"more impact for mission critical integrity asset": {
			confidentiality:              types.Confidential,
			integrity:                    types.MissionCritical,
			availability:                 types.Critical,
			tbType:                       types.ExecutionEnvironment,
			expectedImpact:               types.VeryHighImpact,
			expectedLikelihood:           types.Likely,
			expectedTrustBoundaryMessage: "execution environment",
		},
		"more impact for mission critical availability asset": {
			confidentiality:              types.Confidential,
			integrity:                    types.Critical,
			availability:                 types.MissionCritical,
			tbType:                       types.ExecutionEnvironment,
			expectedImpact:               types.VeryHighImpact,
			expectedLikelihood:           types.Likely,
			expectedTrustBoundaryMessage: "execution environment",
		},
		"same network trust boundary": {
			confidentiality:              types.Confidential,
			integrity:                    types.Critical,
			availability:                 types.Critical,
			tbType:                       types.NetworkOnPrem,
			expectedImpact:               types.HighImpact,
			expectedLikelihood:           types.Unlikely,
			expectedTrustBoundaryMessage: "network segment",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingIdentityProviderIsolationRule()
			tb := &types.TrustBoundary{
				Id:   "tb1",
				Type: testCase.tbType,
			}
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:              "ta1",
						Title:           "Test Technical Asset",
						OutOfScope:      false,
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
						Technologies: types.TechnologyList{
							{
								Name: "some-identity-related-technology",
								Attributes: map[string]bool{
									types.IsIdentityRelated: true,
								},
							},
						},
					},
					"ta2": {
						Id:    "ta2",
						Title: "Test Sparring Technical Asset",
					},
				},
				DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
					"ta1": tb,
					"ta2": tb,
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, testCase.expectedLikelihood, risks[0].ExploitationLikelihood)
			expTitle := fmt.Sprintf("<b>Missing Identity Provider Isolation</b> to further encapsulate and protect identity-related asset <b>Test Technical Asset</b> against unrelated lower protected assets <b>in the same %s</b>, which might be easier to compromise by attackers", testCase.expectedTrustBoundaryMessage)
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}
