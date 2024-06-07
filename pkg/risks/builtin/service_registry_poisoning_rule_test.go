package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestServiceRegistryPoisoningRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewServiceRegistryPoisoningRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestServiceRegistryPoisoningRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewServiceRegistryPoisoningRule()
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

func TestServiceRegistryPoisoningRuleGenerateRisksNoServiceRegistryNoRisksCreated(t *testing.T) {
	rule := NewServiceRegistryPoisoningRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.ServiceRegistry: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type ServiceRegistryPoisoningRuleTest struct {
	confidentiality types.Confidentiality
	integrity       types.Criticality
	availability    types.Criticality

	callerConfidentiality types.Confidentiality
	callerIntegrity       types.Criticality
	callerAvailability    types.Criticality

	communicationLinkDataSentConfidentiality types.Confidentiality
	communicationLinkDataSentIntegrity       types.Criticality
	communicationLinkDataSentAvailability    types.Criticality

	communicationLinkDataReceivedConfidentiality types.Confidentiality
	communicationLinkDataReceivedIntegrity       types.Criticality
	communicationLinkDataReceivedAvailability    types.Criticality

	expectedImpact types.RiskExploitationImpact
}

func TestServiceRegistryPoisoningRuleGenerateRisksRiskCreated(t *testing.T) {
	testCases := map[string]ServiceRegistryPoisoningRuleTest{
		"low impact": {
			confidentiality:                              types.Confidential,
			integrity:                                    types.Critical,
			availability:                                 types.Critical,
			callerConfidentiality:                        types.Confidential,
			callerIntegrity:                              types.Critical,
			callerAvailability:                           types.Critical,
			communicationLinkDataSentConfidentiality:     types.Confidential,
			communicationLinkDataSentIntegrity:           types.Critical,
			communicationLinkDataSentAvailability:        types.Critical,
			communicationLinkDataReceivedConfidentiality: types.Confidential,
			communicationLinkDataReceivedIntegrity:       types.Critical,
			communicationLinkDataReceivedAvailability:    types.Critical,
			expectedImpact:                               types.LowImpact,
		},
		"strictly confidential medium impact": {
			confidentiality:                              types.StrictlyConfidential,
			integrity:                                    types.Critical,
			availability:                                 types.Critical,
			callerConfidentiality:                        types.Confidential,
			callerIntegrity:                              types.Critical,
			callerAvailability:                           types.Critical,
			communicationLinkDataSentConfidentiality:     types.Confidential,
			communicationLinkDataSentIntegrity:           types.Critical,
			communicationLinkDataSentAvailability:        types.Critical,
			communicationLinkDataReceivedConfidentiality: types.Confidential,
			communicationLinkDataReceivedIntegrity:       types.Critical,
			communicationLinkDataReceivedAvailability:    types.Critical,
			expectedImpact:                               types.MediumImpact,
		},
		"mission critical integrity medium impact": {
			confidentiality:                              types.Confidential,
			integrity:                                    types.MissionCritical,
			availability:                                 types.Critical,
			callerConfidentiality:                        types.Confidential,
			callerIntegrity:                              types.Critical,
			callerAvailability:                           types.Critical,
			communicationLinkDataSentConfidentiality:     types.Confidential,
			communicationLinkDataSentIntegrity:           types.Critical,
			communicationLinkDataSentAvailability:        types.Critical,
			communicationLinkDataReceivedConfidentiality: types.Confidential,
			communicationLinkDataReceivedIntegrity:       types.Critical,
			communicationLinkDataReceivedAvailability:    types.Critical,
			expectedImpact:                               types.MediumImpact,
		},
		"mission critical availability medium impact": {
			confidentiality:                              types.Confidential,
			integrity:                                    types.Critical,
			availability:                                 types.MissionCritical,
			callerConfidentiality:                        types.Confidential,
			callerIntegrity:                              types.Critical,
			callerAvailability:                           types.Critical,
			communicationLinkDataSentConfidentiality:     types.Confidential,
			communicationLinkDataSentIntegrity:           types.Critical,
			communicationLinkDataSentAvailability:        types.Critical,
			communicationLinkDataReceivedConfidentiality: types.Confidential,
			communicationLinkDataReceivedIntegrity:       types.Critical,
			communicationLinkDataReceivedAvailability:    types.Critical,
			expectedImpact:                               types.MediumImpact,
		},
		"strictly confidential caller medium impact": {
			confidentiality:                              types.Confidential,
			integrity:                                    types.Critical,
			availability:                                 types.Critical,
			callerConfidentiality:                        types.StrictlyConfidential,
			callerIntegrity:                              types.Critical,
			callerAvailability:                           types.Critical,
			communicationLinkDataSentConfidentiality:     types.Confidential,
			communicationLinkDataSentIntegrity:           types.Critical,
			communicationLinkDataSentAvailability:        types.Critical,
			communicationLinkDataReceivedConfidentiality: types.Confidential,
			communicationLinkDataReceivedIntegrity:       types.Critical,
			communicationLinkDataReceivedAvailability:    types.Critical,
			expectedImpact:                               types.MediumImpact,
		},
		"mission critical caller integration medium impact": {
			confidentiality:                              types.Confidential,
			integrity:                                    types.Critical,
			availability:                                 types.Critical,
			callerConfidentiality:                        types.Confidential,
			callerIntegrity:                              types.MissionCritical,
			callerAvailability:                           types.Critical,
			communicationLinkDataSentConfidentiality:     types.Confidential,
			communicationLinkDataSentIntegrity:           types.Critical,
			communicationLinkDataSentAvailability:        types.Critical,
			communicationLinkDataReceivedConfidentiality: types.Confidential,
			communicationLinkDataReceivedIntegrity:       types.Critical,
			communicationLinkDataReceivedAvailability:    types.Critical,
			expectedImpact:                               types.MediumImpact,
		},
		"mission critical caller availability medium impact": {
			confidentiality:                              types.Confidential,
			integrity:                                    types.Critical,
			availability:                                 types.Critical,
			callerConfidentiality:                        types.Confidential,
			callerIntegrity:                              types.Critical,
			callerAvailability:                           types.MissionCritical,
			communicationLinkDataSentConfidentiality:     types.Confidential,
			communicationLinkDataSentIntegrity:           types.Critical,
			communicationLinkDataSentAvailability:        types.Critical,
			communicationLinkDataReceivedConfidentiality: types.Confidential,
			communicationLinkDataReceivedIntegrity:       types.Critical,
			communicationLinkDataReceivedAvailability:    types.Critical,
			expectedImpact:                               types.MediumImpact,
		},
		"strictly confidential communication link data sent medium impact": {
			confidentiality:                              types.Confidential,
			integrity:                                    types.Critical,
			availability:                                 types.Critical,
			callerConfidentiality:                        types.Confidential,
			callerIntegrity:                              types.Critical,
			callerAvailability:                           types.Critical,
			communicationLinkDataSentConfidentiality:     types.StrictlyConfidential,
			communicationLinkDataSentIntegrity:           types.Critical,
			communicationLinkDataSentAvailability:        types.Critical,
			communicationLinkDataReceivedConfidentiality: types.Confidential,
			communicationLinkDataReceivedIntegrity:       types.Critical,
			communicationLinkDataReceivedAvailability:    types.Critical,
			expectedImpact:                               types.MediumImpact,
		},
		"mission critical communication link data sent availability medium impact": {
			confidentiality:                              types.Confidential,
			integrity:                                    types.Critical,
			availability:                                 types.Critical,
			callerConfidentiality:                        types.Confidential,
			callerIntegrity:                              types.Critical,
			callerAvailability:                           types.Critical,
			communicationLinkDataSentConfidentiality:     types.Confidential,
			communicationLinkDataSentIntegrity:           types.Critical,
			communicationLinkDataSentAvailability:        types.MissionCritical,
			communicationLinkDataReceivedConfidentiality: types.Confidential,
			communicationLinkDataReceivedIntegrity:       types.Critical,
			communicationLinkDataReceivedAvailability:    types.Critical,
			expectedImpact:                               types.MediumImpact,
		},
		"mission critical communication link data sent integrity medium impact": {
			confidentiality:                              types.Confidential,
			integrity:                                    types.Critical,
			availability:                                 types.Critical,
			callerConfidentiality:                        types.Confidential,
			callerIntegrity:                              types.Critical,
			callerAvailability:                           types.Critical,
			communicationLinkDataSentConfidentiality:     types.Confidential,
			communicationLinkDataSentIntegrity:           types.MissionCritical,
			communicationLinkDataSentAvailability:        types.Critical,
			communicationLinkDataReceivedConfidentiality: types.Confidential,
			communicationLinkDataReceivedIntegrity:       types.Critical,
			communicationLinkDataReceivedAvailability:    types.Critical,
			expectedImpact:                               types.MediumImpact,
		},
		"strictly confidential communication link data received medium impact": {
			confidentiality:                              types.Confidential,
			integrity:                                    types.Critical,
			availability:                                 types.Critical,
			callerConfidentiality:                        types.Confidential,
			callerIntegrity:                              types.Critical,
			callerAvailability:                           types.Critical,
			communicationLinkDataSentConfidentiality:     types.Confidential,
			communicationLinkDataSentIntegrity:           types.Critical,
			communicationLinkDataSentAvailability:        types.Critical,
			communicationLinkDataReceivedConfidentiality: types.StrictlyConfidential,
			communicationLinkDataReceivedIntegrity:       types.Critical,
			communicationLinkDataReceivedAvailability:    types.Critical,
			expectedImpact:                               types.MediumImpact,
		},
		"mission critical communication link data received integrity medium impact": {
			confidentiality:                              types.Confidential,
			integrity:                                    types.Critical,
			availability:                                 types.Critical,
			callerConfidentiality:                        types.Confidential,
			callerIntegrity:                              types.Critical,
			callerAvailability:                           types.Critical,
			communicationLinkDataSentConfidentiality:     types.Confidential,
			communicationLinkDataSentIntegrity:           types.Critical,
			communicationLinkDataSentAvailability:        types.Critical,
			communicationLinkDataReceivedConfidentiality: types.Confidential,
			communicationLinkDataReceivedIntegrity:       types.MissionCritical,
			communicationLinkDataReceivedAvailability:    types.Critical,
			expectedImpact:                               types.MediumImpact,
		},
		"mission critical communication link data received availability medium impact": {
			confidentiality:                              types.Confidential,
			integrity:                                    types.Critical,
			availability:                                 types.Critical,
			callerConfidentiality:                        types.Confidential,
			callerIntegrity:                              types.Critical,
			callerAvailability:                           types.Critical,
			communicationLinkDataSentConfidentiality:     types.Confidential,
			communicationLinkDataSentIntegrity:           types.Critical,
			communicationLinkDataSentAvailability:        types.Critical,
			communicationLinkDataReceivedConfidentiality: types.Confidential,
			communicationLinkDataReceivedIntegrity:       types.Critical,
			communicationLinkDataReceivedAvailability:    types.MissionCritical,
			expectedImpact:                               types.MediumImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewServiceRegistryPoisoningRule()
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
									types.ServiceRegistry: true,
								},
							},
						},
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
					},
					"ta2": {
						Id:              "ta2",
						Title:           "Caller Technical Asset",
						OutOfScope:      false,
						Confidentiality: testCase.callerConfidentiality,
						Integrity:       testCase.callerIntegrity,
						Availability:    testCase.callerAvailability,
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"ta1": {
						{
							Title:              "Incoming Flow",
							SourceId:           "ta2",
							DataAssetsSent:     []string{"sent-data"},
							DataAssetsReceived: []string{"received-data"},
						},
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"sent-data": {
						Confidentiality: testCase.communicationLinkDataSentConfidentiality,
						Integrity:       testCase.communicationLinkDataSentIntegrity,
						Availability:    testCase.communicationLinkDataSentAvailability,
					},
					"received-data": {
						Confidentiality: testCase.communicationLinkDataReceivedConfidentiality,
						Integrity:       testCase.communicationLinkDataReceivedIntegrity,
						Availability:    testCase.communicationLinkDataReceivedAvailability,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, "<b>Service Registry Poisoning</b> risk at <b>Test Technical Asset</b>", risks[0].Title)
		})
	}
}
