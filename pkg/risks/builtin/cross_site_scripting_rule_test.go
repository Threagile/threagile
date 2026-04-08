package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestCrossSiteScriptingRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewCrossSiteScriptingRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCrossSiteScriptingRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewCrossSiteScriptingRule()

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

func TestCrossSiteScriptingRuleGenerateRisksTechAssetNotWebApplicationNotRisksCreated(t *testing.T) {
	rule := NewCrossSiteScriptingRule()

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

func TestCrossSiteScriptingRuleGenerateRisksTechAssetWebApplicationRisksCreated(t *testing.T) {
	rule := NewCrossSiteScriptingRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
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
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Cross-Site Scripting (XSS)</b> risk at <b>Web Application</b>", risks[0].Title)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestCrossSiteScriptingRuleGenerateRisksTechAssetProcessStrictlyConfidentialDataAssetHighImpactRiskCreated(t *testing.T) {
	rule := NewCrossSiteScriptingRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Web Application",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
				DataAssetsProcessed: []string{"strictly-confidential-data-asset"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"strictly-confidential-data-asset": {
				Confidentiality: types.StrictlyConfidential,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Cross-Site Scripting (XSS)</b> risk at <b>Web Application</b>", risks[0].Title)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}

func TestCrossSiteScriptingRuleGenerateRisksTechAssetProcessMissionCriticalIntegrityDataHighImpactRiskCreated(t *testing.T) {
	rule := NewCrossSiteScriptingRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Web Application",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
				DataAssetsProcessed: []string{"mission-critical-data-asset"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"mission-critical-data-asset": {
				Integrity: types.MissionCritical,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Cross-Site Scripting (XSS)</b> risk at <b>Web Application</b>", risks[0].Title)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}

func TestCrossSiteScriptingRuleGenerateRisksTechAssetNoDataProcessedMediumImpactRiskCreated(t *testing.T) {
	rule := NewCrossSiteScriptingRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Web Application",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
				DataAssetsProcessed: []string{},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Cross-Site Scripting (XSS)</b> risk at <b>Web Application</b>", risks[0].Title)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestCrossSiteScriptingRuleGenerateRisksMultipleWebApplicationsEachGeneratesOwnRisk(t *testing.T) {
	rule := NewCrossSiteScriptingRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Web Application One",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Web Application Two",
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
	assert.Len(t, risks, 2)
	riskTitles := []string{risks[0].Title, risks[1].Title}
	assert.Contains(t, riskTitles, "<b>Cross-Site Scripting (XSS)</b> risk at <b>Web Application One</b>")
	assert.Contains(t, riskTitles, "<b>Cross-Site Scripting (XSS)</b> risk at <b>Web Application Two</b>")
}

func TestCrossSiteScriptingRuleGenerateRisksTechAssetProcessBothConfidentialAndStrictlyConfidentialHighImpactRiskCreated(t *testing.T) {
	rule := NewCrossSiteScriptingRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Web Application",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.WebApplication: true,
						},
					},
				},
				DataAssetsProcessed: []string{"confidential-data-asset", "strictly-confidential-data-asset"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"confidential-data-asset": {
				Confidentiality: types.Confidential,
			},
			"strictly-confidential-data-asset": {
				Confidentiality: types.StrictlyConfidential,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Cross-Site Scripting (XSS)</b> risk at <b>Web Application</b>", risks[0].Title)
	// Highest confidentiality wins: StrictlyConfidential → HighImpact
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}
