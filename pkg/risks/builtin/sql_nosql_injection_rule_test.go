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

func TestSqlNoSqlInjectionRuleGenerateRisksThreeFlowsOnlyOneRiskyFlowExactlyOneRisk(t *testing.T) {
	rule := NewSqlNoSqlInjectionRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta-db": {
				Id:         "ta-db",
				Title:      "Database",
				OutOfScope: false,
				Type:       types.Datastore,
				Technologies: types.TechnologyList{
					{
						Name: "database",
						Attributes: map[string]bool{
							types.IsVulnerableToQueryInjection: true,
						},
					},
				},
			},
			"ta-caller1": {
				Id:    "ta-caller1",
				Title: "Caller One",
			},
			"ta-caller2": {
				Id:    "ta-caller2",
				Title: "Caller Two",
			},
			"ta-caller3": {
				Id:    "ta-caller3",
				Title: "Caller Three",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta-db": {
				{
					Id:       "flow1",
					Title:    "Risky DB Flow",
					TargetId: "ta-db",
					SourceId: "ta-caller1",
					Protocol: types.JdbcEncrypted,
				},
				{
					Id:       "flow2",
					Title:    "Non-Vulnerable DB Flow",
					TargetId: "ta-db",
					SourceId: "ta-caller2",
					Protocol: types.JDBC,
				},
				{
					Id:       "flow3",
					Title:    "Non-DB Flow",
					TargetId: "ta-db",
					SourceId: "ta-caller3",
					Protocol: types.SmbEncrypted,
				},
			},
		},
	})

	// flow1: JdbcEncrypted (database protocol) + isVulnerableToQueryInjection=true -> risk
	// flow2: JDBC (database protocol) + isVulnerableToQueryInjection=true -> also a risk (both callers have vulnerable db protocols)
	// flow3: SmbEncrypted (not a database protocol, not lax) -> no risk
	assert.Nil(t, err)
	assert.Len(t, risks, 2)
}

func TestSqlNoSqlInjectionRuleGenerateRisksMultipleDatastoresEachWithRiskyFlowGeneratesOwnRisk(t *testing.T) {
	rule := NewSqlNoSqlInjectionRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta-db1": {
				Id:         "ta-db1",
				Title:      "Database One",
				OutOfScope: false,
				Type:       types.Datastore,
				Technologies: types.TechnologyList{
					{
						Name: "database",
						Attributes: map[string]bool{
							types.IsVulnerableToQueryInjection: true,
						},
					},
				},
			},
			"ta-db2": {
				Id:         "ta-db2",
				Title:      "Database Two",
				OutOfScope: false,
				Type:       types.Datastore,
				Technologies: types.TechnologyList{
					{
						Name: "database",
						Attributes: map[string]bool{
							types.IsVulnerableToQueryInjection: true,
						},
					},
				},
			},
			"ta-caller": {
				Id:    "ta-caller",
				Title: "Caller Asset",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta-db1": {
				{
					Id:       "flow-to-db1",
					Title:    "Flow to DB1",
					TargetId: "ta-db1",
					SourceId: "ta-caller",
					Protocol: types.JdbcEncrypted,
				},
			},
			"ta-db2": {
				{
					Id:       "flow-to-db2",
					Title:    "Flow to DB2",
					TargetId: "ta-db2",
					SourceId: "ta-caller",
					Protocol: types.JdbcEncrypted,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 2)
}

func TestSqlNoSqlInjectionRuleGenerateRisksLaxDatabaseProtocolNotVulnerableAttributeStillCreatesRisk(t *testing.T) {
	rule := NewSqlNoSqlInjectionRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "NoSQL Database",
				OutOfScope: false,
				Type:       types.Datastore,
				Technologies: types.TechnologyList{
					{
						Name: "nosql-database",
						Attributes: map[string]bool{
							types.IsVulnerableToQueryInjection: false,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "REST Client",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					Id:       "rest-flow",
					Title:    "REST Flow",
					TargetId: "ta1",
					SourceId: "ta2",
					Protocol: types.HTTP,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	// Lax protocol always triggers regardless of IsVulnerableToQueryInjection attribute
	assert.Equal(t, types.VeryLikely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestSqlNoSqlInjectionRuleGenerateRisksNonDevOpsUsageVeryLikelyLikelihood(t *testing.T) {
	rule := NewSqlNoSqlInjectionRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Database",
				OutOfScope: false,
				Type:       types.Datastore,
				Technologies: types.TechnologyList{
					{
						Name: "database",
						Attributes: map[string]bool{
							types.IsVulnerableToQueryInjection: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Application Server",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					Id:       "app-flow",
					Title:    "App Flow",
					TargetId: "ta1",
					SourceId: "ta2",
					Protocol: types.JdbcEncrypted,
					Usage:    types.Business,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.VeryLikely, risks[0].ExploitationLikelihood)
}

func TestSqlNoSqlInjectionRuleGenerateRisksDevOpsUsageLikelyLikelihood(t *testing.T) {
	rule := NewSqlNoSqlInjectionRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Database",
				OutOfScope: false,
				Type:       types.Datastore,
				Technologies: types.TechnologyList{
					{
						Name: "database",
						Attributes: map[string]bool{
							types.IsVulnerableToQueryInjection: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "DevOps Tool",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					Id:       "devops-flow",
					Title:    "DevOps Flow",
					TargetId: "ta1",
					SourceId: "ta2",
					Protocol: types.JdbcEncrypted,
					Usage:    types.DevOps,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
}

func TestSqlNoSqlInjectionRuleGenerateRisksConfidentialDataNotStrictlyConfidentialMediumImpact(t *testing.T) {
	rule := NewSqlNoSqlInjectionRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:              "ta1",
				Title:           "Database",
				OutOfScope:      false,
				Type:            types.Datastore,
				Confidentiality: types.Confidential,
				Technologies: types.TechnologyList{
					{
						Name: "database",
						Attributes: map[string]bool{
							types.IsVulnerableToQueryInjection: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Application",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					Id:       "app-flow",
					Title:    "App Flow",
					TargetId: "ta1",
					SourceId: "ta2",
					Protocol: types.JdbcEncrypted,
					Usage:    types.Business,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	// Confidential is not StrictlyConfidential, so impact is MediumImpact (not HighImpact)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}
