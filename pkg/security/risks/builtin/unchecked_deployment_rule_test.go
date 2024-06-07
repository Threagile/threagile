package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestUncheckedDeploymentRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewUncheckedDeploymentRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUncheckedDeploymentRuleGenerateRisksNotDevelopmentRelevantNoRisksCreated(t *testing.T) {
	rule := NewUncheckedDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: true,
				Technologies: types.TechnologyList{
					{
						Name: "development-relevant",
						Attributes: map[string]bool{
							types.IsDevelopmentRelevant: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type UncheckedDeploymentRuleTest struct {
	dataAssetIntegrity         types.Criticality
	targetAssetConfidentiality types.Confidentiality
	targetAssetIntegrity       types.Criticality
	targetAssetAvailability    types.Criticality

	usage types.Usage

	expectedImpact types.RiskExploitationImpact
}

func TestUncheckedDeploymentRuleGenerateRisks(t *testing.T) {
	testCases := map[string]UncheckedDeploymentRuleTest{
		"not devops usage": {
			dataAssetIntegrity:         types.Operational,
			targetAssetConfidentiality: types.Restricted,
			targetAssetIntegrity:       types.Important,
			targetAssetAvailability:    types.Important,
			usage:                      types.Business,
			expectedImpact:             types.LowImpact,
		},
		"operational data asset sent low impact": {
			dataAssetIntegrity:         types.Operational,
			targetAssetConfidentiality: types.Restricted,
			targetAssetIntegrity:       types.Important,
			targetAssetAvailability:    types.Important,
			usage:                      types.DevOps,
			expectedImpact:             types.LowImpact,
		},
		"important data asset sent": {
			dataAssetIntegrity:         types.Important,
			targetAssetConfidentiality: types.Restricted,
			targetAssetIntegrity:       types.Important,
			targetAssetAvailability:    types.Important,
			usage:                      types.DevOps,
			expectedImpact:             types.LowImpact,
		},
		"important data asset sent to confidental asset": {
			dataAssetIntegrity:         types.Important,
			targetAssetConfidentiality: types.Confidential,
			targetAssetIntegrity:       types.Important,
			targetAssetAvailability:    types.Important,
			usage:                      types.DevOps,
			expectedImpact:             types.MediumImpact,
		},
		"important data asset sent to critical integrity asset": {
			dataAssetIntegrity:         types.Important,
			targetAssetConfidentiality: types.Restricted,
			targetAssetIntegrity:       types.Critical,
			targetAssetAvailability:    types.Important,
			usage:                      types.DevOps,
			expectedImpact:             types.MediumImpact,
		},
		"important data asset sent to critical available asset": {
			dataAssetIntegrity:         types.Important,
			targetAssetConfidentiality: types.Restricted,
			targetAssetIntegrity:       types.Important,
			targetAssetAvailability:    types.Critical,
			usage:                      types.DevOps,
			expectedImpact:             types.MediumImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewUncheckedDeploymentRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:    "ta1",
						Title: "Test Technical Asset",
						Technologies: types.TechnologyList{
							{
								Name: "development-relevant",
								Attributes: map[string]bool{
									types.IsDevelopmentRelevant: true,
								},
							},
						},
						CommunicationLinks: []*types.CommunicationLink{
							{
								TargetId:       "ta2",
								Usage:          testCase.usage,
								DataAssetsSent: []string{"sent-data"},
							},
						},
					},
					"ta2": {
						Id:              "ta2",
						Title:           "Target Technical Asset",
						Confidentiality: testCase.targetAssetConfidentiality,
						Integrity:       testCase.targetAssetIntegrity,
						Availability:    testCase.targetAssetAvailability,
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"sent-data": {
						Integrity: testCase.dataAssetIntegrity,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, "<b>Unchecked Deployment</b> risk at <b>Test Technical Asset</b>", risks[0].Title)
		})
	}
}
