package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestContainerPlatformEscapeRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewContainerPlatformEscapeRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestContainerPlatformEscapeRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewContainerPlatformEscapeRule()

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

func TestContainerPlatformEscapeRuleRuleGenerateRisksTechAssetNotContainerPlatformNotRisksCreated(t *testing.T) {
	rule := NewContainerPlatformEscapeRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.ContainerPlatform: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestContainerPlatformEscapeRuleGenerateRisksTechAssetContainerPlatformRisksCreated(t *testing.T) {
	rule := NewContainerPlatformEscapeRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Docker",
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.ContainerPlatform: true,
						},
					},
				},
				Machine: types.Container,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Container Platform Escape</b> risk at <b>Docker</b>", risks[0].Title)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.NotEmpty(t, risks[0].DataBreachTechnicalAssetIDs)
	assert.Equal(t, "ta1", risks[0].DataBreachTechnicalAssetIDs[0])
}

func TestContainerPlatformEscapeRuleGenerateRisksTechAssetProcessedConfidentialityStrictlyConfidentialDataAssetHighImpactRiskCreated(t *testing.T) {
	rule := NewContainerPlatformEscapeRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Docker",
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.ContainerPlatform: true,
						},
					},
				},
				Machine:             types.Container,
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
	assert.Equal(t, "<b>Container Platform Escape</b> risk at <b>Docker</b>", risks[0].Title)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
	assert.NotEmpty(t, risks[0].DataBreachTechnicalAssetIDs)
	assert.Equal(t, "ta1", risks[0].DataBreachTechnicalAssetIDs[0])
}

func TestContainerPlatformEscapeRuleGenerateRisksTechAssetProcessedIntegrityMissionCriticalDataAssetHighImpactRiskCreated(t *testing.T) {
	rule := NewContainerPlatformEscapeRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Docker",
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.ContainerPlatform: true,
						},
					},
				},
				Machine:             types.Container,
				DataAssetsProcessed: []string{"strictly-confidential-data-asset"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"strictly-confidential-data-asset": {
				Integrity: types.MissionCritical,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Container Platform Escape</b> risk at <b>Docker</b>", risks[0].Title)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
	assert.NotEmpty(t, risks[0].DataBreachTechnicalAssetIDs)
	assert.Equal(t, "ta1", risks[0].DataBreachTechnicalAssetIDs[0])
}

func TestContainerPlatformEscapeRuleGenerateRisksTechAssetProcessedAvailabilityMissionCriticalDataAssetHighImpactRiskCreated(t *testing.T) {
	rule := NewContainerPlatformEscapeRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Docker",
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.ContainerPlatform: true,
						},
					},
				},
				Machine:             types.Container,
				DataAssetsProcessed: []string{"strictly-confidential-data-asset"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"strictly-confidential-data-asset": {
				Availability: types.MissionCritical,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Container Platform Escape</b> risk at <b>Docker</b>", risks[0].Title)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
	assert.NotEmpty(t, risks[0].DataBreachTechnicalAssetIDs)
	assert.Equal(t, "ta1", risks[0].DataBreachTechnicalAssetIDs[0])
}
