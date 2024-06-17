package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestMissingFileValidationRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewMissingFileValidationRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingFileValidationRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewMissingFileValidationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				OutOfScope:           true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingFileValidationRuleGenerateRisksNotCustomlyDevelopedTechnicalAssetNoRisksCreated(t *testing.T) {
	rule := NewMissingFileValidationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: false,
				OutOfScope:           false,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingFileValidationRuleGenerateRisksNoFileAcceptedAssetNoRisksCreated(t *testing.T) {
	rule := NewMissingFileValidationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				OutOfScope:           false,
				DataFormatsAccepted:  []types.DataFormat{types.CSV, types.Serialization, types.XML},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingFileValidationRuleGenerateRisksFileDataFormatsAcceptedRisksCreated(t *testing.T) {
	rule := NewMissingFileValidationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				OutOfScope:           false,
				DataFormatsAccepted:  []types.DataFormat{types.File},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing File Validation</b> risk at <b>Test Technical Asset</b>", risks[0].Title)
}

func TestMissingFileValidationRuleGenerateRisksProcessStrictlyConfidentialDataRisksCreatedWithMediumImpact(t *testing.T) {
	rule := NewMissingFileValidationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				OutOfScope:           false,
				DataFormatsAccepted:  []types.DataFormat{types.File},
				DataAssetsProcessed:  []string{"da1"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Title:           "Test Data Asset",
				Confidentiality: types.StrictlyConfidential,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing File Validation</b> risk at <b>Test Technical Asset</b>", risks[0].Title)
}

func TestMissingFileValidationRuleGenerateRisksProcessMissionCriticalIntegrityDataRisksCreatedWithMediumImpact(t *testing.T) {
	rule := NewMissingFileValidationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				OutOfScope:           false,
				DataFormatsAccepted:  []types.DataFormat{types.File},
				DataAssetsProcessed:  []string{"da1"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Title:     "Test Data Asset",
				Integrity: types.MissionCritical,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing File Validation</b> risk at <b>Test Technical Asset</b>", risks[0].Title)
}

func TestMissingFileValidationRuleGenerateRisksProcessMissionCriticalAvailabilityDataRisksCreatedWithMediumImpact(t *testing.T) {
	rule := NewMissingFileValidationRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				OutOfScope:           false,
				DataFormatsAccepted:  []types.DataFormat{types.File},
				DataAssetsProcessed:  []string{"da1"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Title:        "Test Data Asset",
				Availability: types.MissionCritical,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing File Validation</b> risk at <b>Test Technical Asset</b>", risks[0].Title)
}
