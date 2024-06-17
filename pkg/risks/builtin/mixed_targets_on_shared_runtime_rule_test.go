package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestMixedTargetsOnSharedRuntimeRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewMixedTargetsOnSharedRuntimeRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMixedTargetsOnSharedRuntimeRuleGenerateRisksAllFrontendTechAssetNoRisksCreated(t *testing.T) {
	rule := NewMixedTargetsOnSharedRuntimeRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "First Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "front-end",
						Attributes: map[string]bool{
							types.IsExclusivelyFrontendRelated: true,
						},
					},
				},
			},
			"ta2": {
				Title: "Second Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "front-end",
						Attributes: map[string]bool{
							types.IsExclusivelyFrontendRelated: true,
						},
					},
				},
			},
		},
		SharedRuntimes: map[string]*types.SharedRuntime{
			"sr1": {
				Title:                  "Shared Runtime",
				TechnicalAssetsRunning: []string{"ta1", "ta2"},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMixedTargetsOnSharedRuntimeRuleGenerateRisksAllBackendTechAssetNoRisksCreated(t *testing.T) {
	rule := NewMixedTargetsOnSharedRuntimeRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "First Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "back-end",
						Attributes: map[string]bool{
							types.IsExclusivelyBackendRelated: true,
						},
					},
				},
			},
			"ta2": {
				Title: "Second Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "back-end",
						Attributes: map[string]bool{
							types.IsExclusivelyBackendRelated: true,
						},
					},
				},
			},
		},
		SharedRuntimes: map[string]*types.SharedRuntime{
			"sr1": {
				Title:                  "Shared Runtime",
				TechnicalAssetsRunning: []string{"ta1", "ta2"},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type MixedTargetsOnSharedRuntimeRuleTest struct {
	confidentiality types.Confidentiality
	integrity       types.Criticality
	availability    types.Criticality

	expectedImpact types.RiskExploitationImpact
}

func TestMixedTargetsOnSharedRuntimeRuleGenerateRisksMixedFrontendBackendTechAssetRiskCreated(t *testing.T) {
	testCases := map[string]MixedTargetsOnSharedRuntimeRuleTest{
		"low impact": {
			confidentiality: types.Confidential,
			integrity:       types.Critical,
			availability:    types.Critical,
			expectedImpact:  types.LowImpact,
		},
		"strictly confidential medium impact": {
			confidentiality: types.StrictlyConfidential,
			integrity:       types.Critical,
			availability:    types.Critical,
			expectedImpact:  types.MediumImpact,
		},
		"mission critical integrity medium impact": {
			confidentiality: types.Confidential,
			integrity:       types.MissionCritical,
			availability:    types.Critical,
			expectedImpact:  types.MediumImpact,
		},
		"mission critical availability medium impact": {
			confidentiality: types.Confidential,
			integrity:       types.Critical,
			availability:    types.MissionCritical,
			expectedImpact:  types.MediumImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMixedTargetsOnSharedRuntimeRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:    "ta1",
						Title: "First Technical Asset",
						Technologies: types.TechnologyList{
							{
								Name: "back-end",
								Attributes: map[string]bool{
									types.IsExclusivelyBackendRelated: true,
								},
							},
						},
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
					},
					"ta2": {
						Id:    "ta2",
						Title: "Second Technical Asset",
						Technologies: types.TechnologyList{
							{
								Name: "front-end",
								Attributes: map[string]bool{
									types.IsExclusivelyFrontendRelated: true,
								},
							},
						},
					},
				},
				SharedRuntimes: map[string]*types.SharedRuntime{
					"sr1": {
						Title:                  "Shared Runtime",
						TechnicalAssetsRunning: []string{"ta1", "ta2"},
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)

			expTitle := "<b>Mixed Targets on Shared Runtime</b> named <b>Shared Runtime</b> might enable attackers moving from one less valuable target to a more valuable one"
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}

func TestMixedTargetsOnSharedRuntimeRuleGenerateRisksMixedTrustBoundaryRiskCreated(t *testing.T) {
	testCases := map[string]MixedTargetsOnSharedRuntimeRuleTest{
		"low impact": {
			confidentiality: types.Confidential,
			integrity:       types.Critical,
			availability:    types.Critical,
			expectedImpact:  types.LowImpact,
		},
		"strictly confidential medium impact": {
			confidentiality: types.StrictlyConfidential,
			integrity:       types.Critical,
			availability:    types.Critical,
			expectedImpact:  types.MediumImpact,
		},
		"mission critical integrity medium impact": {
			confidentiality: types.Confidential,
			integrity:       types.MissionCritical,
			availability:    types.Critical,
			expectedImpact:  types.MediumImpact,
		},
		"mission critical availability medium impact": {
			confidentiality: types.Confidential,
			integrity:       types.Critical,
			availability:    types.MissionCritical,
			expectedImpact:  types.MediumImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMixedTargetsOnSharedRuntimeRule()
			tb1 := &types.TrustBoundary{
				Id:                    "tb1",
				Title:                 "Test Trust Boundary",
				TechnicalAssetsInside: []string{"ta1"},
				Type:                  types.NetworkCloudProvider,
			}
			tb2 := &types.TrustBoundary{
				Id:                    "tb2",
				Title:                 "Test Trust Boundary",
				TechnicalAssetsInside: []string{"ta2"},
				Type:                  types.NetworkCloudProvider,
			}
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:    "ta1",
						Title: "First Technical Asset",
						Technologies: types.TechnologyList{
							{
								Name: "back-end",
								Attributes: map[string]bool{
									types.IsExclusivelyBackendRelated: true,
								},
							},
						},
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
					},
					"ta2": {
						Id:    "ta2",
						Title: "Second Technical Asset",
						Technologies: types.TechnologyList{
							{
								Name: "front-end",
								Attributes: map[string]bool{
									types.IsExclusivelyBackendRelated: true,
								},
							},
						},
					},
				},
				SharedRuntimes: map[string]*types.SharedRuntime{
					"sr1": {
						Title:                  "Shared Runtime",
						TechnicalAssetsRunning: []string{"ta1", "ta2"},
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
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)

			expTitle := "<b>Mixed Targets on Shared Runtime</b> named <b>Shared Runtime</b> might enable attackers moving from one less valuable target to a more valuable one"
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}
