package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestCrossSiteRequestForgeryRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				OutOfScope: true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksTechAssetNotWebApplicationNotRisksCreated(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.WebApplication: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksTechAssetWebApplicationWithoutIncomingCommunicationNotRisksCreated(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksTechAssetWebApplicationIncomingRequestNotWebAccessProtocolNotRiskCreated(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"web-app": {
				Id: "web-app",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"file-scrapper": {
				Technologies: types.TechnologyList{
					{
						Name: "tool",
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"web-app": {
				{
					Protocol: types.LocalFileAccess,
					SourceId: "file-scrapper",
					TargetId: "web-app",
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksTechAssetWebApplicationIncomingRequestWebAccessProtocolRiskCreated(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"web-app": {
				Id:    "web-app",
				Title: "Web Application",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"user": {
				Title: "user",
				Technologies: types.TechnologyList{
					{
						Name: "user",
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"web-app": {
				{
					Title:    "HTTP",
					Protocol: types.HTTP,
					SourceId: "user",
					TargetId: "web-app",
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Cross-Site Request Forgery (CSRF)</b> risk at <b>Web Application</b> via <b>HTTP</b> from <b>user</b>", risks[0].Title)
	assert.Equal(t, types.VeryLikely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksTechAssetWebApplicationIncomingRequestWebAccessProtocolViaDevOpsRiskCreatedWithLikelyLikelihood(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"web-app": {
				Id:    "web-app",
				Title: "Web Application",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"ci/cd": {
				Title: "ci/cd",
				Technologies: types.TechnologyList{
					{
						Name: "ci/cd",
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"web-app": {
				{
					Title:    "HTTP",
					Protocol: types.HTTP,
					SourceId: "ci/cd",
					TargetId: "web-app",
					Usage:    types.DevOps,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Cross-Site Request Forgery (CSRF)</b> risk at <b>Web Application</b> via <b>HTTP</b> from <b>ci/cd</b>", risks[0].Title)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksTechAssetWebApplicationIncomingRequestWebAccessProtocolRiskCreatedWithMediumImpactWhenIntegrityIsMissionCritical(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"web-app": {
				Id:    "web-app",
				Title: "Web Application",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"user": {
				Title: "user",
				Technologies: types.TechnologyList{
					{
						Name: "user",
					},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"mission-critical-data": {
				Id:        "mission-critical-data",
				Title:     "Mission Critical Data",
				Integrity: types.MissionCritical,
			},
		},

		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"web-app": {
				{
					Title:              "HTTP",
					Protocol:           types.HTTP,
					SourceId:           "user",
					TargetId:           "web-app",
					DataAssetsReceived: []string{"mission-critical-data"},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Cross-Site Request Forgery (CSRF)</b> risk at <b>Web Application</b> via <b>HTTP</b> from <b>user</b>", risks[0].Title)
	assert.Equal(t, types.VeryLikely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}
