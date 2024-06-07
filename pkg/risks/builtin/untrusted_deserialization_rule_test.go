package builtin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestUntrustedDeserializationRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewUntrustedDeserializationRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUntrustedDeserializationRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewUntrustedDeserializationRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				OutOfScope: true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUntrustedDeserializationRuleGenerateRisksNoSerializationRisksCreated(t *testing.T) {
	rule := NewUntrustedDeserializationRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id: "ta1",
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUntrustedDeserializationRuleGenerateRiskAcceptSerializationRisksCreated(t *testing.T) {
	rule := NewUntrustedDeserializationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:                  "ta1",
				Title:               "Test Technical Asset",
				DataFormatsAccepted: []types.DataFormat{types.Serialization},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Untrusted Deserialization</b> risk at <b>Test Technical Asset</b>", risks[0].Title)
}

func TestUntrustedDeserializationRuleGenerateRiskEJBRisksCreated(t *testing.T) {
	rule := NewUntrustedDeserializationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Test Technical Asset",
				Technologies: types.TechnologyList{
					{
						Attributes: map[string]bool{
							types.EJB: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Untrusted Deserialization</b> risk at <b>Test Technical Asset</b>", risks[0].Title)
}

type UntrustedDeserialisationRuleTest struct {
	confidentiality types.Confidentiality
	integrity       types.Criticality
	availability    types.Criticality
	protocol        types.Protocol

	isAcrossTrustBoundary bool

	expectedImpact      types.RiskExploitationImpact
	expectedLikelihood  types.RiskExploitationLikelihood
	expectedSuffixTitle string
}

func TestUntrustedDeserializationRuleGenerateRisks(t *testing.T) {
	testCases := map[string]UntrustedDeserialisationRuleTest{
		"IIOP": {
			confidentiality:       types.Confidential,
			integrity:             types.Critical,
			availability:          types.Critical,
			protocol:              types.IIOP,
			isAcrossTrustBoundary: false,

			expectedImpact:     types.HighImpact,
			expectedLikelihood: types.Likely,
		},
		"IiopEncrypted": {
			confidentiality:       types.Confidential,
			integrity:             types.Critical,
			availability:          types.Critical,
			protocol:              types.IiopEncrypted,
			isAcrossTrustBoundary: false,

			expectedImpact:     types.HighImpact,
			expectedLikelihood: types.Likely,
		},
		"JRMP": {
			confidentiality:       types.Confidential,
			integrity:             types.Critical,
			availability:          types.Critical,
			protocol:              types.JRMP,
			isAcrossTrustBoundary: false,

			expectedImpact:     types.HighImpact,
			expectedLikelihood: types.Likely,
		},
		"JrmpEncrypted": {
			confidentiality:       types.Confidential,
			integrity:             types.Critical,
			availability:          types.Critical,
			protocol:              types.JrmpEncrypted,
			isAcrossTrustBoundary: false,

			expectedImpact:     types.HighImpact,
			expectedLikelihood: types.Likely,
		},
		"strictly confidential": {
			confidentiality:       types.StrictlyConfidential,
			integrity:             types.Critical,
			availability:          types.Critical,
			protocol:              types.IIOP,
			isAcrossTrustBoundary: false,

			expectedImpact:     types.VeryHighImpact,
			expectedLikelihood: types.Likely,
		},
		"mission critical integrity": {
			confidentiality:       types.Confidential,
			integrity:             types.MissionCritical,
			availability:          types.Critical,
			protocol:              types.IIOP,
			isAcrossTrustBoundary: false,

			expectedImpact:     types.VeryHighImpact,
			expectedLikelihood: types.Likely,
		},
		"mission critical availability": {
			confidentiality:       types.Confidential,
			integrity:             types.Critical,
			availability:          types.MissionCritical,
			protocol:              types.IIOP,
			isAcrossTrustBoundary: false,

			expectedImpact:     types.VeryHighImpact,
			expectedLikelihood: types.Likely,
		},
		"across trust boundary": {
			confidentiality:       types.Confidential,
			integrity:             types.Critical,
			availability:          types.Critical,
			protocol:              types.IIOP,
			isAcrossTrustBoundary: true,

			expectedImpact:      types.HighImpact,
			expectedLikelihood:  types.VeryLikely,
			expectedSuffixTitle: " across a trust boundary (at least via communication link <b>Test Communication Link</b>)",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewUntrustedDeserializationRule()
			tb1 := &types.TrustBoundary{
				Id:                    "tb1",
				Title:                 "First Trust Boundary",
				TechnicalAssetsInside: []string{"source", "target"},
				Type:                  types.NetworkCloudProvider,
			}
			tb2 := &types.TrustBoundary{
				Id:    "tb2",
				Title: "Second Trust Boundary",
				Type:  types.NetworkCloudProvider,
			}
			if testCase.isAcrossTrustBoundary {
				tb1.TechnicalAssetsInside = []string{"source"}
				tb2.TechnicalAssetsInside = []string{"target"}
			}
			directContainingTrustBoundaryMappedByTechnicalAssetId := map[string]*types.TrustBoundary{
				"source": tb1,
				"target": tb1,
			}
			if testCase.isAcrossTrustBoundary {
				directContainingTrustBoundaryMappedByTechnicalAssetId["target"] = tb2
			}

			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"source": {
						Id:    "source",
						Title: "Source Technical Asset",
						CommunicationLinks: []*types.CommunicationLink{
							{
								Title:    "Test Communication Link",
								SourceId: "source",
								TargetId: "target",
								Protocol: testCase.protocol,
							},
						},
					},
					"target": {
						Id:              "target",
						Title:           "Target Technical Asset",
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
					},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{
					"tb1": tb1,
					"tb2": tb2,
				},
				DirectContainingTrustBoundaryMappedByTechnicalAssetId: directContainingTrustBoundaryMappedByTechnicalAssetId,
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"target": {
						{
							SourceId: "source",
							TargetId: "target",
							Protocol: testCase.protocol,
							Title:    "Test Communication Link",
						},
					},
				},
			})

			assert.Nil(t, err)
			assert.NotEmpty(t, risks)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, testCase.expectedLikelihood, risks[0].ExploitationLikelihood)
			expectedMessage := fmt.Sprintf("<b>Untrusted Deserialization</b> risk at <b>Target Technical Asset</b>%s", testCase.expectedSuffixTitle)
			assert.Equal(t, risks[0].Title, expectedMessage)
		})
	}
}
