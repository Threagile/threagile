package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestContainerBaseImageBackdooringRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewContainerBaseImageBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestContainerBaseImageBackdooringRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewContainerBaseImageBackdooringRule()

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

func TestContainerBaseImageBackdooringRuleMachineIsNotContainerNotRisksCreated(t *testing.T) {
	rule := NewContainerBaseImageBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Machine: types.Virtual,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestContainerBaseImageBackdooringRuleMachineIsContainerRiskCreated(t *testing.T) {
	rule := NewContainerBaseImageBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Machine: types.Container,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
}

func TestContainerBaseImageBackdooringRuleGenerateRisksTechAssetProcessedConfidentialityStrictlyConfidentialDataAssetHighImpactRiskCreated(t *testing.T) {
	rule := NewContainerBaseImageBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Machine:             types.Container,
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
	assert.Equal(t, len(risks), 1)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}

func TestContainerBaseImageBackdooringRuleGenerateRisksTechAssetProcessedIntegrityMissionCriticalDataAssetHighImpactRiskCreated(t *testing.T) {
	rule := NewContainerBaseImageBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Machine:             types.Container,
				DataAssetsProcessed: []string{"critical-data-asset", "mission-critical-data-asset"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"critical-data-asset": {
				Integrity: types.Critical,
			},
			"mission-critical-data-asset": {
				Integrity: types.MissionCritical,
			},
		},
	})

	assert.Nil(t, err)
	assert.Equal(t, len(risks), 1)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}

func TestContainerBaseImageBackdooringRuleGenerateRisksTechAssetProcessedAvailabilityMissionCriticalDataAssetHighImpactRiskCreated(t *testing.T) {
	rule := NewContainerBaseImageBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Machine:             types.Container,
				DataAssetsProcessed: []string{"critical-data-asset", "mission-critical-data-asset"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"critical-data-asset": {
				Availability: types.Critical,
			},
			"mission-critical-data-asset": {
				Availability: types.MissionCritical,
			},
		},
	})

	assert.Nil(t, err)
	assert.Equal(t, len(risks), 1)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}
