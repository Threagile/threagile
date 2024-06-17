package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestMissingIdentityPropagationRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewMissingIdentityPropagationRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingIdentityPropagationRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewMissingIdentityPropagationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: true,
				RAA:        100,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type MissingIdentityPropagationRuleRisksCreatedTest struct {
	multitenant         bool
	confidentiality     types.Confidentiality
	integrity           types.Criticality
	availability        types.Criticality
	technologyAttribute string

	callerType                types.TechnicalAssetType
	callerTechnologyAttribute string

	communicationLinkAuthentication types.Authentication
	communicationLinkAuthorization  types.Authorization
	communicationLinkUsage          types.Usage

	expectedImpact types.RiskExploitationImpact
}

func TestMissingIdentityPropagationRuleRisksCreated(t *testing.T) {
	testCases := map[string]MissingIdentityPropagationRuleRisksCreatedTest{
		"confidential tech asset called from not data store": {
			multitenant:                     false,
			confidentiality:                 types.Confidential,
			integrity:                       types.Important,
			availability:                    types.Important,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
		"strictly confidential tech asset called from not data store": {
			multitenant:                     false,
			confidentiality:                 types.StrictlyConfidential,
			integrity:                       types.Important,
			availability:                    types.Important,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.MediumImpact,
		},
		"restricted multitenant tech asset called from not data store": {
			multitenant:                     true,
			confidentiality:                 types.Restricted,
			integrity:                       types.Operational,
			availability:                    types.Operational,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
		"critically integrity tech asset called from not data store": {
			multitenant:                     false,
			confidentiality:                 types.Restricted,
			integrity:                       types.Critical,
			availability:                    types.Important,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
		"mission critically integrity tech asset called from not data store": {
			multitenant:                     false,
			confidentiality:                 types.Restricted,
			integrity:                       types.MissionCritical,
			availability:                    types.Important,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.MediumImpact,
		},
		"important integrity multitenant tech asset called from not data store": {
			multitenant:                     true,
			confidentiality:                 types.Internal,
			integrity:                       types.Important,
			availability:                    types.Operational,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
		"critically availability tech asset called from not data store": {
			multitenant:                     false,
			confidentiality:                 types.Restricted,
			integrity:                       types.Important,
			availability:                    types.Critical,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
		"mission critically availability tech asset called from not data store": {
			multitenant:                     false,
			confidentiality:                 types.Restricted,
			integrity:                       types.Important,
			availability:                    types.MissionCritical,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.MediumImpact,
		},
		"business technical user called from data store": {
			multitenant:                     true,
			confidentiality:                 types.Internal,
			integrity:                       types.Operational,
			availability:                    types.Important,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.TechnicalUser,
			communicationLinkUsage:          types.Business,
			expectedImpact:                  types.LowImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingIdentityPropagationRule()
			input := &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:              "ta1",
						Title:           "Test Technical Asset",
						MultiTenant:     testCase.multitenant,
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
						Technologies: types.TechnologyList{
							{
								Name:       "some-technology",
								Attributes: map[string]bool{},
							},
						},
					},
					"caller": {
						Id:              "caller",
						Title:           "Test Caller Technical Asset",
						MultiTenant:     testCase.multitenant,
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
						Type:            testCase.callerType,
						Technologies: types.TechnologyList{
							{
								Name:       "some-technology",
								Attributes: map[string]bool{},
							},
						},
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"ta1": {
						{
							Title:          "Test Communication Link",
							SourceId:       "caller",
							TargetId:       "ta1",
							Authentication: testCase.communicationLinkAuthentication,
							Authorization:  testCase.communicationLinkAuthorization,
							Usage:          testCase.communicationLinkUsage,
						},
					},
				},
			}
			input.TechnicalAssets["ta1"].Technologies[0].Attributes[testCase.technologyAttribute] = true
			input.TechnicalAssets["caller"].Technologies[0].Attributes[testCase.callerTechnologyAttribute] = true

			risks, err := rule.GenerateRisks(input)

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, "<b>Missing End User Identity Propagation</b> over communication link <b>Test Communication Link</b> from <b>Test Caller Technical Asset</b> to <b>Test Technical Asset</b>", risks[0].Title)
		})
	}
}

func TestMissingIdentityPropagationRuleRisksNotCreated(t *testing.T) {
	testCases := map[string]MissingIdentityPropagationRuleRisksCreatedTest{
		"cia lower to not create risk": {
			multitenant:                     false,
			confidentiality:                 types.Restricted,
			integrity:                       types.Important,
			availability:                    types.Important,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
		"cia lower to not create risk for multitenant": {
			multitenant:                     true,
			confidentiality:                 types.Internal,
			integrity:                       types.Operational,
			availability:                    types.Operational,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
		"is not processing end request": {
			multitenant:                     false,
			confidentiality:                 types.Confidential,
			integrity:                       types.Important,
			availability:                    types.Important,
			technologyAttribute:             types.UnknownTechnology,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
		"caller from data store": {
			multitenant:                     false,
			confidentiality:                 types.Confidential,
			integrity:                       types.Critical,
			availability:                    types.Critical,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.Datastore,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
		"caller not able to propagate identity to outgoing targets": {
			multitenant:                     false,
			confidentiality:                 types.Confidential,
			integrity:                       types.Critical,
			availability:                    types.Critical,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.UnknownTechnology,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
		"none authentication in communication link": {
			multitenant:                     false,
			confidentiality:                 types.Confidential,
			integrity:                       types.Critical,
			availability:                    types.Critical,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.NoneAuthentication,
			communicationLinkAuthorization:  types.NoneAuthorization,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
		"not enduser identity propagation authorization": {
			multitenant:                     false,
			confidentiality:                 types.Confidential,
			integrity:                       types.Critical,
			availability:                    types.Critical,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.EndUserIdentityPropagation,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
		"devops without none authorization": {
			multitenant:                     false,
			confidentiality:                 types.Confidential,
			integrity:                       types.Critical,
			availability:                    types.Critical,
			technologyAttribute:             types.IsUsuallyProcessingEndUserRequests,
			callerType:                      types.ExternalEntity,
			callerTechnologyAttribute:       types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets,
			communicationLinkAuthentication: types.ClientCertificate,
			communicationLinkAuthorization:  types.TechnicalUser,
			communicationLinkUsage:          types.DevOps,
			expectedImpact:                  types.LowImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingIdentityPropagationRule()
			input := &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:              "ta1",
						Title:           "Test Technical Asset",
						MultiTenant:     testCase.multitenant,
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
						Technologies: types.TechnologyList{
							{
								Name:       "some-technology",
								Attributes: map[string]bool{},
							},
						},
					},
					"caller": {
						Id:              "caller",
						Title:           "Test Caller Technical Asset",
						MultiTenant:     testCase.multitenant,
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
						Type:            testCase.callerType,
						Technologies: types.TechnologyList{
							{
								Name:       "some-technology",
								Attributes: map[string]bool{},
							},
						},
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"ta1": {
						{
							Title:          "Test Communication Link",
							SourceId:       "caller",
							TargetId:       "ta1",
							Authentication: testCase.communicationLinkAuthentication,
							Authorization:  testCase.communicationLinkAuthorization,
							Usage:          testCase.communicationLinkUsage,
						},
					},
				},
			}
			input.TechnicalAssets["ta1"].Technologies[0].Attributes[testCase.technologyAttribute] = true
			input.TechnicalAssets["caller"].Technologies[0].Attributes[testCase.callerTechnologyAttribute] = true

			risks, err := rule.GenerateRisks(input)

			assert.Nil(t, err)
			assert.Empty(t, risks, 1)
		})
	}
}
