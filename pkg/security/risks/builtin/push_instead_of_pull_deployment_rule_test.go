package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestPushInsteadPullDeploymentRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewPushInsteadPullDeploymentRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestPushInsteadPullDeploymentRuleGenerateRisksNoBuildPipelineNoRisksCreated(t *testing.T) {
	rule := NewPushInsteadPullDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Build Pipeline Technical Asset",
				OutOfScope: true,
				Technologies: types.TechnologyList{
					{
						Name: "build pipeline",
						Attributes: map[string]bool{
							types.BuildPipeline: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestPushInsteadPullDeploymentRuleGenerateRisksNoCommunicationWithBuildPipelineNoRisksCreated(t *testing.T) {
	rule := NewPushInsteadPullDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Build Pipeline Technical Asset",
				OutOfScope: true,
				Technologies: types.TechnologyList{
					{
						Name: "build pipeline",
						Attributes: map[string]bool{
							types.BuildPipeline: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestPushInsteadPullDeploymentRuleGenerateRisksReadOnlyCommunicationWithBuildPipelineNoRisksCreated(t *testing.T) {
	rule := NewPushInsteadPullDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Build Pipeline Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "build pipeline",
						Attributes: map[string]bool{
							types.BuildPipeline: true,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						TargetId: "ta2",
						Readonly: true,
						Usage:    types.Business,
					},
				},
			},
			"ta2": {
				Id:         "ta2",
				Title:      "Target Pipeline Technical Asset",
				OutOfScope: false,
				Usage:      types.Business,
				Technologies: types.TechnologyList{
					{
						Name: "build pipeline",
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

func TestPushInsteadPullDeploymentRuleGenerateRisksTargetOutOfScopeWithBuildPipelineNoRisksCreated(t *testing.T) {
	rule := NewPushInsteadPullDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Build Pipeline Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "build pipeline",
						Attributes: map[string]bool{
							types.BuildPipeline: true,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						TargetId: "ta2",
						Readonly: false,
						Usage:    types.DevOps,
					},
				},
			},
			"ta2": {
				Id:         "ta2",
				Title:      "Target Pipeline Technical Asset",
				OutOfScope: true,
				Usage:      types.Business,
				Technologies: types.TechnologyList{
					{
						Name: "build pipeline",
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

func TestPushInsteadPullDeploymentRuleGenerateRisksDevOpsUsageNoRisksCreated(t *testing.T) {
	rule := NewPushInsteadPullDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Build Pipeline Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "build pipeline",
						Attributes: map[string]bool{
							types.BuildPipeline: true,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						TargetId: "ta2",
						Readonly: false,
						Usage:    types.DevOps,
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Target Pipeline Technical Asset",
				Usage: types.DevOps,
				Technologies: types.TechnologyList{
					{
						Name: "build pipeline",
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

func TestPushInsteadPullDeploymentRuleGenerateRisksTargetIsDevOpsUsageNoRisksCreated(t *testing.T) {
	rule := NewPushInsteadPullDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Build Pipeline Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "build pipeline",
						Attributes: map[string]bool{
							types.BuildPipeline: true,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						TargetId: "ta2",
						Readonly: false,
						Usage:    types.DevOps,
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Target Pipeline Technical Asset",
				Usage: types.DevOps,
				Technologies: types.TechnologyList{
					{
						Name: "build pipeline",
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

func TestPushInsteadPullDeploymentRuleGenerateRisksTargetIsDevelopmentRelatedNoRisksCreated(t *testing.T) {
	rule := NewPushInsteadPullDeploymentRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Build Pipeline Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "build pipeline",
						Attributes: map[string]bool{
							types.BuildPipeline: true,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						TargetId: "ta2",
						Readonly: false,
						Usage:    types.DevOps,
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Target Pipeline Technical Asset",
				Usage: types.Business,
				Technologies: types.TechnologyList{
					{
						Name: "build pipeline",
						Attributes: map[string]bool{
							types.IsDevelopmentRelevant: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type PushInsteadOfPullRuleTest struct {
	confidentiality types.Confidentiality
	integrity       types.Criticality
	availability    types.Criticality

	expectedImpact types.RiskExploitationImpact
}

func TestPushInsteadOfPullRuleGenerateRisksRiskCreated(t *testing.T) {
	testCases := map[string]PushInsteadOfPullRuleTest{
		"low impact": {
			confidentiality: types.Restricted,
			integrity:       types.Important,
			availability:    types.Important,
			expectedImpact:  types.LowImpact,
		},
		"confidential medium impact": {
			confidentiality: types.Confidential,
			integrity:       types.Important,
			availability:    types.Important,
			expectedImpact:  types.MediumImpact,
		},
		"critical integrity medium impact": {
			confidentiality: types.Restricted,
			integrity:       types.Critical,
			availability:    types.Important,
			expectedImpact:  types.MediumImpact,
		},
		"critical availability medium impact": {
			confidentiality: types.Restricted,
			integrity:       types.Important,
			availability:    types.Critical,
			expectedImpact:  types.MediumImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewPushInsteadPullDeploymentRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:    "ta1",
						Title: "Build Pipeline Technical Asset",
						Technologies: types.TechnologyList{
							{
								Name: "build pipeline",
								Attributes: map[string]bool{
									types.BuildPipeline: true,
								},
							},
						},
						CommunicationLinks: []*types.CommunicationLink{
							{
								Title:    "Test Communication Link",
								TargetId: "ta2",
								Readonly: false,
								Usage:    types.DevOps,
							},
						},
					},
					"ta2": {
						Id:    "ta2",
						Title: "Target Pipeline Technical Asset",
						Usage: types.Business,
						Technologies: types.TechnologyList{
							{
								Name: "build pipeline",
								Attributes: map[string]bool{
									types.IsDevelopmentRelevant: false,
								},
							},
						},
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)

			expTitle := "<b>Push instead of Pull Deployment</b> at <b>Target Pipeline Technical Asset</b> via build pipeline asset <b>Build Pipeline Technical Asset</b>"
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}
