package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestSearchQueryInjectionRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewSearchQueryInjectionRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestSearchQueryInjectionRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewSearchQueryInjectionRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: true,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsSearchRelated: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestSearchQueryInjectionRuleGenerateRisksNotSearchRelatedNoRisksCreated(t *testing.T) {
	rule := NewSearchQueryInjectionRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsSearchRelated: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestSearchQueryInjectionRuleGenerateRisksNoIncomingCommunicationLinkNoRisksCreated(t *testing.T) {
	rule := NewSearchQueryInjectionRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsSearchRelated: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestSearchQueryInjectionRuleGenerateRisksCallerOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewSearchQueryInjectionRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsSearchRelated: true,
						},
					},
				},
			},
			"ta2": {
				Id:         "ta2",
				Title:      "Caller Technical Asset",
				OutOfScope: true,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId: "ta2",
					Protocol: types.HTTP,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestSearchQueryInjectionRuleGenerateRisksNoHTTPOrBinaryCommunicationNoRisksCreated(t *testing.T) {
	rule := NewSearchQueryInjectionRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsSearchRelated: true,
						},
					},
				},
			},
			"ta2": {
				Id:         "ta2",
				Title:      "Caller Technical Asset",
				OutOfScope: false,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId: "ta2",
					Protocol: types.JDBC,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type SearchQueryInjectionRuleTest struct {
	confidentiality types.Confidentiality
	integrity       types.Criticality
	protocol        types.Protocol
	usage           types.Usage

	expectedImpact     types.RiskExploitationImpact
	expectedLikelihood types.RiskExploitationLikelihood
}

func TestSearchQueryInjectionRuleGenerateRisksRiskCreated(t *testing.T) {
	testCases := map[string]SearchQueryInjectionRuleTest{
		"medium impact": {
			confidentiality:    types.Confidential,
			integrity:          types.Critical,
			protocol:           types.HTTP,
			usage:              types.Business,
			expectedImpact:     types.MediumImpact,
			expectedLikelihood: types.VeryLikely,
		},
		"strictly confidential medium impact": {
			confidentiality:    types.StrictlyConfidential,
			integrity:          types.Critical,
			protocol:           types.HTTP,
			usage:              types.Business,
			expectedImpact:     types.HighImpact,
			expectedLikelihood: types.VeryLikely,
		},
		"mission critical integrity medium impact": {
			confidentiality:    types.Confidential,
			integrity:          types.Critical,
			protocol:           types.HTTP,
			expectedImpact:     types.MediumImpact,
			expectedLikelihood: types.VeryLikely,
		},
		"low impact": {
			confidentiality:    types.Internal,
			integrity:          types.Operational,
			protocol:           types.HTTP,
			usage:              types.Business,
			expectedImpact:     types.LowImpact,
			expectedLikelihood: types.VeryLikely,
		},
		"HTTPS protocol": {
			confidentiality:    types.Confidential,
			integrity:          types.Critical,
			protocol:           types.HTTPS,
			usage:              types.Business,
			expectedImpact:     types.MediumImpact,
			expectedLikelihood: types.VeryLikely,
		},
		"Binary protocol": {
			confidentiality:    types.Confidential,
			integrity:          types.Critical,
			protocol:           types.BINARY,
			usage:              types.Business,
			expectedImpact:     types.MediumImpact,
			expectedLikelihood: types.VeryLikely,
		},
		"Binary encrypted protocol": {
			confidentiality:    types.Confidential,
			integrity:          types.Critical,
			protocol:           types.BinaryEncrypted,
			usage:              types.Business,
			expectedImpact:     types.MediumImpact,
			expectedLikelihood: types.VeryLikely,
		},
		"devops usage": {
			confidentiality:    types.Confidential,
			integrity:          types.Critical,
			protocol:           types.BinaryEncrypted,
			usage:              types.DevOps,
			expectedImpact:     types.MediumImpact,
			expectedLikelihood: types.VeryLikely,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewSearchQueryInjectionRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:         "ta1",
						Title:      "Test Technical Asset",
						OutOfScope: false,
						Technologies: types.TechnologyList{
							{
								Name: "service-registry",
								Attributes: map[string]bool{
									types.IsSearchRelated: true,
								},
							},
						},
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
					},
					"ta2": {
						Id:         "ta2",
						Title:      "Caller Technical Asset",
						OutOfScope: false,
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"ta1": {
						{
							Title:    "Call to ta1",
							SourceId: "ta2",
							Protocol: testCase.protocol,
							Usage:    testCase.usage,
						},
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)

			expTitle := "<b>Search Query Injection</b> risk at <b>Caller Technical Asset</b> against search engine server <b>Test Technical Asset</b> via <b>Call to ta1</b>"
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}
