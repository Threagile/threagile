package builtin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestMissingNetworkSegmentationRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewMissingNetworkSegmentationRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingNetworkSegmentationRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewMissingNetworkSegmentationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				OutOfScope:           true,
				RAA:                  55,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsNoNetworkSegmentationRequired: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingNetworkSegmentationRuleGenerateRisksNoNetworkSegmentationRequiredNoRisksCreated(t *testing.T) {
	rule := NewMissingNetworkSegmentationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				RAA:        55,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsNoNetworkSegmentationRequired: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingNetworkSegmentationRuleGenerateRisksLowRAANoNetworkSegmentationRequired(t *testing.T) {
	rule := NewMissingNetworkSegmentationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "Test Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsNoNetworkSegmentationRequired: true,
						},
					},
				},
				RAA: 45,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingNetworkSegmentationRuleGenerateRisksNotDataStoreAndLowCIABNoRisksCreated(t *testing.T) {
	rule := NewMissingNetworkSegmentationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsNoNetworkSegmentationRequired: true,
						},
					},
				},
				RAA:             55,
				Type:            types.Process,
				Confidentiality: types.Restricted,
				Integrity:       types.Important,
				Availability:    types.Important,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type MissingNetworkSegmentationRuleTest struct {
	confidentiality types.Confidentiality
	integrity       types.Criticality
	availability    types.Criticality

	expectedImpact types.RiskExploitationImpact
}

func TestMissingNetworkSegmentationRuleGenerateRisksRiskCreated(t *testing.T) {
	testCases := map[string]MissingNetworkSegmentationRuleTest{
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
			rule := NewMissingNetworkSegmentationRule()
			tb1 := &types.TrustBoundary{
				Id:                    "tb1",
				Title:                 "Test Trust Boundary",
				TechnicalAssetsInside: []string{"ta1"},
				Type:                  types.NetworkCloudProvider,
			}
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:         "ta1",
						OutOfScope: false,
						Technologies: types.TechnologyList{
							{
								Name: "service-registry",
								Attributes: map[string]bool{
									types.IsNoNetworkSegmentationRequired: true,
								},
							},
						},
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
						RAA:             55,
						Title:           "First Technical Asset",
					},
					"ta2": {
						Id:    "ta2",
						Title: "Second Technical Asset",
						Technologies: types.TechnologyList{
							{
								Name: "artifact-registry",
								Attributes: map[string]bool{
									types.IsLessProtectedType:                true,
									types.IsCloseToHighValueTargetsTolerated: false,
								},
							},
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

			expTitle := fmt.Sprintf("<b>Missing Network Segmentation</b> to further encapsulate and protect <b>%s</b> against unrelated "+
				"lower protected assets in the same network segment, which might be easier to compromise by attackers", "First Technical Asset")
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}

func TestMissingNetworkSegmentationRuleGenerateRisksSparringAssetIsNotLessProtectedNoRisksCreated(t *testing.T) {
	rule := NewMissingNetworkSegmentationRule()
	tb1 := &types.TrustBoundary{
		Id:                    "tb1",
		Title:                 "Test Trust Boundary",
		TechnicalAssetsInside: []string{"ta1"},
		Type:                  types.NetworkCloudProvider,
	}
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsNoNetworkSegmentationRequired: true,
						},
					},
				},
				Type:  types.Datastore,
				RAA:   55,
				Title: "First Technical Asset",
			},
			"ta2": {
				Id:    "ta2",
				Title: "Second Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "artifact-registry",
						Attributes: map[string]bool{
							types.IsLessProtectedType:                false,
							types.IsCloseToHighValueTargetsTolerated: false,
						},
					},
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
	assert.Empty(t, risks)
}

func TestMissingNetworkSegmentationRuleGenerateRisksSparringAssetCloseToHighValueTargetsToleratedNoRisksCreated(t *testing.T) {
	rule := NewMissingNetworkSegmentationRule()
	tb1 := &types.TrustBoundary{
		Id:                    "tb1",
		Title:                 "Test Trust Boundary",
		TechnicalAssetsInside: []string{"ta1"},
		Type:                  types.NetworkCloudProvider,
	}
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsNoNetworkSegmentationRequired: true,
						},
					},
				},
				Type:  types.Datastore,
				RAA:   55,
				Title: "First Technical Asset",
			},
			"ta2": {
				Id:    "ta2",
				Title: "Second Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "artifact-registry",
						Attributes: map[string]bool{
							types.IsLessProtectedType:                true,
							types.IsCloseToHighValueTargetsTolerated: true,
						},
					},
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
	assert.Empty(t, risks)
}

func TestMissingNetworkSegmentationRuleGenerateRisksNotSameTrustBoundaryNoRisksCreated(t *testing.T) {
	rule := NewMissingNetworkSegmentationRule()
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
				Id:         "ta1",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsNoNetworkSegmentationRequired: true,
						},
					},
				},
				Type:  types.Datastore,
				RAA:   55,
				Title: "First Technical Asset",
			},
			"ta2": {
				Id:    "ta2",
				Title: "Second Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "artifact-registry",
						Attributes: map[string]bool{
							types.IsLessProtectedType:                true,
							types.IsCloseToHighValueTargetsTolerated: false,
						},
					},
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

func TestMissingNetworkSegmentationHasDirectConnectionNoRisksCreated(t *testing.T) {
	rule := NewMissingNetworkSegmentationRule()
	tb1 := &types.TrustBoundary{
		Id:                    "tb1",
		Title:                 "Test Trust Boundary",
		TechnicalAssetsInside: []string{"ta1"},
		Type:                  types.NetworkCloudProvider,
	}
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsNoNetworkSegmentationRequired: true,
						},
					},
				},
				Type:  types.Datastore,
				RAA:   55,
				Title: "First Technical Asset",
			},
			"ta2": {
				Id:    "ta2",
				Title: "Second Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "artifact-registry",
						Attributes: map[string]bool{
							types.IsLessProtectedType:                true,
							types.IsCloseToHighValueTargetsTolerated: false,
						},
					},
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
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId: "ta2",
					TargetId: "ta1",
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}
