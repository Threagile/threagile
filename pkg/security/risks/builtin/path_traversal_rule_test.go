package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestPathTraversalRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewPathTraversalRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestPathTraversalRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewPathTraversalRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: true,
				Technologies: types.TechnologyList{
					{
						Name: "file-storage",
						Attributes: map[string]bool{
							types.IsFileStorage: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestPathTraversalRuleGenerateRisksNotFileStorageNoRisksCreated(t *testing.T) {
	rule := NewPathTraversalRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "file-storage",
						Attributes: map[string]bool{
							types.IsFileStorage: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestPathTraversalRuleGenerateRisksFileStorageWithoutIncomingCommunicationLinksNoRisksCreated(t *testing.T) {
	rule := NewPathTraversalRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "file-storage",
						Attributes: map[string]bool{
							types.IsFileStorage: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestPathTraversalRuleGenerateRisksCallerOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewPathTraversalRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "file-storage",
						Attributes: map[string]bool{
							types.IsFileStorage: true,
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
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type PathTraversalRuleTest struct {
	confidentiality    types.Confidentiality
	integrity          types.Criticality
	communicationUsage types.Usage

	expectedImpact     types.RiskExploitationImpact
	expectedLikelihood types.RiskExploitationLikelihood
}

func TestPathTraversalRuleGenerateRisksRiskCreated(t *testing.T) {
	testCases := map[string]PathTraversalRuleTest{
		"medium impact": {
			confidentiality:    types.Confidential,
			integrity:          types.Critical,
			communicationUsage: types.Business,
			expectedImpact:     types.MediumImpact,
			expectedLikelihood: types.VeryLikely,
		},
		"strictly confidential high impact": {
			confidentiality:    types.StrictlyConfidential,
			integrity:          types.Critical,
			communicationUsage: types.Business,
			expectedImpact:     types.HighImpact,
			expectedLikelihood: types.VeryLikely,
		},
		"mission critical integrity high impact": {
			confidentiality:    types.Confidential,
			integrity:          types.MissionCritical,
			communicationUsage: types.Business,
			expectedImpact:     types.HighImpact,
			expectedLikelihood: types.VeryLikely,
		},
		"devops usage likelihood likely": {
			confidentiality:    types.Confidential,
			integrity:          types.Critical,
			communicationUsage: types.DevOps,
			expectedImpact:     types.MediumImpact,
			expectedLikelihood: types.Likely,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {

			rule := NewPathTraversalRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:         "ta1",
						Title:      "Test Technical Asset",
						OutOfScope: false,
						Technologies: types.TechnologyList{
							{
								Name: "file-storage",
								Attributes: map[string]bool{
									types.IsFileStorage: true,
								},
							},
						},
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
					},
					"ta2": {
						Id:    "ta2",
						Title: "Caller Technical Asset",
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"ta1": {
						{
							Title:    "Call File Storage",
							SourceId: "ta2",
							Usage:    testCase.communicationUsage,
						},
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, testCase.expectedLikelihood, risks[0].ExploitationLikelihood)

			expTitle := "<b>Path-Traversal</b> risk at <b>Caller Technical Asset</b> against filesystem <b>Test Technical Asset</b> via <b>Call File Storage</b>"
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}
