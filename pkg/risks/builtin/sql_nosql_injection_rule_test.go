package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestSqlNoSqlInjectionRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewSqlNoSqlInjectionRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestSqlNoSqlInjectionRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewSqlNoSqlInjectionRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: true,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.ServiceRegistry: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type SqlNoSqlInjectionRuleTest struct {
	confidentiality types.Confidentiality
	integrity       types.Criticality
	usage           types.Usage
	assetType       types.TechnicalAssetType

	protocol                     types.Protocol
	isVulnerableToQueryInjection bool

	expectRiskCreated  bool
	expectedLikelihood types.RiskExploitationLikelihood
	expectedImpact     types.RiskExploitationImpact
}

func TestSqlNoSqlInjectionRuleCreateRisks(t *testing.T) {
	testCases := map[string]SqlNoSqlInjectionRuleTest{
		"not database protocol": {
			assetType:                    types.Datastore,
			protocol:                     types.SmbEncrypted,
			expectRiskCreated:            false,
			isVulnerableToQueryInjection: true,
		},
		"not vulnerable to query injection not lax": {
			assetType:                    types.Datastore,
			protocol:                     types.JdbcEncrypted,
			expectRiskCreated:            false,
			isVulnerableToQueryInjection: false,
		},
		"lax database always vulnerable to query injection": {
			assetType:                    types.Datastore,
			protocol:                     types.HTTP,
			isVulnerableToQueryInjection: false,
			expectRiskCreated:            true,
			expectedLikelihood:           types.VeryLikely,
			expectedImpact:               types.MediumImpact,
		},
		"no datastore": {
			assetType:                    types.Process,
			protocol:                     types.JdbcEncrypted,
			isVulnerableToQueryInjection: true,
			expectRiskCreated:            false,
		},
		"database protocol and vulnerable to query injection": {
			assetType:                    types.Datastore,
			protocol:                     types.JdbcEncrypted,
			expectRiskCreated:            true,
			isVulnerableToQueryInjection: true,
			expectedLikelihood:           types.VeryLikely,
			expectedImpact:               types.MediumImpact,
		},
		"strictly confidential tech asset high impact": {
			assetType:                    types.Datastore,
			protocol:                     types.JdbcEncrypted,
			expectRiskCreated:            true,
			isVulnerableToQueryInjection: true,
			confidentiality:              types.StrictlyConfidential,
			integrity:                    types.Critical,
			expectedLikelihood:           types.VeryLikely,
			expectedImpact:               types.HighImpact,
		},
		"mission critical integrity tech asset high impact": {
			assetType:                    types.Datastore,
			protocol:                     types.JdbcEncrypted,
			expectRiskCreated:            true,
			isVulnerableToQueryInjection: true,
			confidentiality:              types.Confidential,
			integrity:                    types.MissionCritical,
			expectedLikelihood:           types.VeryLikely,
			expectedImpact:               types.HighImpact,
		},
		"devops usage likely likelihood": {
			assetType:                    types.Datastore,
			protocol:                     types.JdbcEncrypted,
			expectRiskCreated:            true,
			isVulnerableToQueryInjection: true,
			usage:                        types.DevOps,
			confidentiality:              types.Confidential,
			integrity:                    types.Critical,
			expectedLikelihood:           types.Likely,
			expectedImpact:               types.MediumImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewSqlNoSqlInjectionRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:         "ta1",
						Title:      "Test Technical Asset",
						OutOfScope: false,
						Type:       testCase.assetType,
						Technologies: types.TechnologyList{
							{
								Name: "service-registry",
								Attributes: map[string]bool{
									types.IsVulnerableToQueryInjection: testCase.isVulnerableToQueryInjection,
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
							Title:    "Incoming Flow",
							TargetId: "ta1",
							SourceId: "ta2",
							Protocol: testCase.protocol,
							Usage:    testCase.usage,
						},
					},
				},
			})

			assert.Nil(t, err)
			if testCase.expectRiskCreated {
				assert.Len(t, risks, 1)
				assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
				assert.Equal(t, testCase.expectedLikelihood, risks[0].ExploitationLikelihood)
				assert.Equal(t, "<b>SQL/NoSQL-Injection</b> risk at <b>Caller Technical Asset</b> against database <b>Test Technical Asset</b> via <b>Incoming Flow</b>", risks[0].Title)
			} else {
				assert.Empty(t, risks)
			}
		})
	}
}
