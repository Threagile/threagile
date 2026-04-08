package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
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

func TestUncheckedDeploymentRuleGenerateRisksSingleDevAssetDeployingToThreeTargets(t *testing.T) {
	rule := NewUncheckedDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta-dev": {
				Id:    "ta-dev",
				Title: "CI/CD Pipeline",
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
						TargetId:       "ta-target1",
						Usage:          types.DevOps,
						DataAssetsSent: []string{"code-asset"},
					},
					{
						TargetId:       "ta-target2",
						Usage:          types.DevOps,
						DataAssetsSent: []string{"code-asset"},
					},
					{
						TargetId:       "ta-target3",
						Usage:          types.DevOps,
						DataAssetsSent: []string{"code-asset"},
					},
				},
			},
			"ta-target1": {
				Id:              "ta-target1",
				Title:           "Low Sensitivity Target",
				Confidentiality: types.Restricted,
				Integrity:       types.Important,
				Availability:    types.Important,
			},
			"ta-target2": {
				Id:              "ta-target2",
				Title:           "Confidential Target",
				Confidentiality: types.Confidential,
				Integrity:       types.Important,
				Availability:    types.Important,
			},
			"ta-target3": {
				Id:              "ta-target3",
				Title:           "Critical Integrity Target",
				Confidentiality: types.Restricted,
				Integrity:       types.Critical,
				Availability:    types.Important,
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"code-asset": {
				Integrity: types.Important,
			},
		},
	})

	assert.Nil(t, err)
	// One risk for the single development-relevant asset
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unchecked Deployment</b> risk at <b>CI/CD Pipeline</b>", risks[0].Title)
	// Impact is MediumImpact because at least one target has high enough sensitivity
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestUncheckedDeploymentRuleGenerateRisksMultipleDevelopmentRelevantAssetsEachGeneratesOwnRisk(t *testing.T) {
	rule := NewUncheckedDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta-dev1": {
				Id:    "ta-dev1",
				Title: "Build Pipeline A",
				Technologies: types.TechnologyList{
					{
						Name: "development-relevant",
						Attributes: map[string]bool{
							types.IsDevelopmentRelevant: true,
						},
					},
				},
			},
			"ta-dev2": {
				Id:    "ta-dev2",
				Title: "Build Pipeline B",
				Technologies: types.TechnologyList{
					{
						Name: "development-relevant",
						Attributes: map[string]bool{
							types.IsDevelopmentRelevant: true,
						},
					},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 2)
}

func TestUncheckedDeploymentRuleGenerateRisksSecondDataAssetWithImportantIntegrityDetectedAsCode(t *testing.T) {
	rule := NewUncheckedDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Build Pipeline",
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
						Usage:          types.DevOps,
						DataAssetsSent: []string{"operational-data", "important-data"},
					},
				},
			},
			"ta2": {
				Id:              "ta2",
				Title:           "Target Asset",
				Confidentiality: types.Confidential,
				Integrity:       types.Important,
				Availability:    types.Important,
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"operational-data": {
				Integrity: types.Operational,
			},
			"important-data": {
				Integrity: types.Important,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	// The second data asset has Important integrity, so deployment target is detected and MediumImpact applies
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestUncheckedDeploymentRuleGenerateRisksDevOpsLinkWithCriticalIntegrityDataDetectedAsCode(t *testing.T) {
	rule := NewUncheckedDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Build Pipeline",
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
						Usage:          types.DevOps,
						DataAssetsSent: []string{"critical-data"},
					},
				},
			},
			"ta2": {
				Id:              "ta2",
				Title:           "Target Asset",
				Confidentiality: types.Confidential,
				Integrity:       types.Important,
				Availability:    types.Important,
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"critical-data": {
				Integrity: types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	// Critical integrity >= Important, so code deployment is detected; Confidential target -> MediumImpact
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestUncheckedDeploymentRuleGenerateRisksNonDevOpsLinkWithImportantIntegrityDataNoDeploymentTarget(t *testing.T) {
	rule := NewUncheckedDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Build Pipeline",
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
						Usage:          types.Business,
						DataAssetsSent: []string{"important-data"},
					},
				},
			},
			"ta2": {
				Id:              "ta2",
				Title:           "Target Asset",
				Confidentiality: types.Confidential,
				Integrity:       types.Important,
				Availability:    types.Important,
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"important-data": {
				Integrity: types.Important,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	// Non-DevOps usage link skipped, so target is not detected as deployment target -> LowImpact
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}
