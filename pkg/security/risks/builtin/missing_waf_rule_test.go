package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestMissingWafRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewMissingWafRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingWafRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewMissingWafRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: true,
				Technologies: types.TechnologyList{
					{
						Name: "not-web-application",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingWafRuleGenerateRisksNotWebApplicationOrServiceNoRisksCreated(t *testing.T) {
	rule := NewMissingWafRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "not-web-application",
						Attributes: map[string]bool{
							types.WebApplication: false,
							types.IsWebService:   false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingWafRuleGenerateRisksNotAccrossBoundaryNetworkNoRisksCreated(t *testing.T) {
	rule := NewMissingWafRule()
	tb1 := &types.TrustBoundary{
		Id:                    "tb1",
		Title:                 "Test Trust Boundary",
		TechnicalAssetsInside: []string{"ta1"},
		Type:                  types.NetworkCloudProvider,
	}
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Test Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "web-application",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Caller Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "web-application",
						Attributes: map[string]bool{
							types.WAF: false,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					TargetId: "ta1",
					SourceId: "ta2",
					Protocol: types.HTTP,
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

func TestMissingWafRuleGenerateRisksWebApplicationFirewallCallNoRisksCreated(t *testing.T) {
	rule := NewMissingWafRule()
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
				Title: "Test Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "web-application",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Caller Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "web-application",
						Attributes: map[string]bool{
							types.WAF: true,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					TargetId: "ta1",
					SourceId: "ta2",
					Protocol: types.HTTP,
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

func TestMissingWafRuleGenerateRisksNotWebAccessProtocolNoRisksCreated(t *testing.T) {
	rule := NewMissingWafRule()
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
				Title: "Test Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "web-application",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Caller Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "web-application",
						Attributes: map[string]bool{
							types.WAF: false,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					TargetId: "ta1",
					SourceId: "ta2",
					Protocol: types.SqlAccessProtocol,
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

type MissingWafRuleTest struct {
	confidentiality types.Confidentiality
	integrity       types.Criticality
	availability    types.Criticality

	expectedImpact types.RiskExploitationImpact
}

func TestMissingWafSegmentationRuleGenerateRisksRiskCreated(t *testing.T) {
	testCases := map[string]MissingWafRuleTest{
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
			rule := NewMissingWafRule()
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
								Name: "web-application",
								Attributes: map[string]bool{
									types.WebApplication: true,
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
								Name: "web-application",
								Attributes: map[string]bool{
									types.WAF: false,
								},
							},
						},
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"ta1": {
						{
							TargetId: "ta1",
							SourceId: "ta2",
							Protocol: types.HTTPS,
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
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)

			expTitle := "<b>Missing Web Application Firewall (WAF)</b> risk at <b>First Technical Asset</b>"
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}
