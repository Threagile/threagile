/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package model

import (
	"testing"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/risks"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestDefaultInputNotFail(t *testing.T) {
	parsedModel, err := ParseModel(createInputModel(map[string]input.TechnicalAsset{}), map[string]risks.RiskRule{}, map[string]*CustomRisk{})

	assert.NoError(t, err)
	assert.NotNil(t, parsedModel)
}

func TestInferConfidentiality_NotSet_NoOthers_ExpectTODO(t *testing.T) {
	ta := map[string]input.TechnicalAsset{}

	taUndefinedConfidentiality := createDefaultTechnicalAsset()
	taUndefinedConfidentiality.Confidentiality = ""
	ta[taUndefinedConfidentiality.ID] = taUndefinedConfidentiality

	parsedModel, err := ParseModel(createInputModel(ta), map[string]risks.RiskRule{}, map[string]*CustomRisk{})

	assert.NoError(t, err)
	// TODO: rename test and check if everyone agree that by default it should be public if there are no other assets
	assert.Equal(t, types.Public, parsedModel.TechnicalAssets[taUndefinedConfidentiality.ID].Confidentiality)
}

func TestInferConfidentiality_NotSet_ExpectHighestConfidentiality(t *testing.T) {
	ta := map[string]input.TechnicalAsset{}

	taUndefinedConfidentiality := createDefaultTechnicalAsset()
	taUndefinedConfidentiality.Confidentiality = ""
	ta[taUndefinedConfidentiality.ID] = taUndefinedConfidentiality

	taLowerConfidentiality := createDefaultTechnicalAsset()
	taLowerConfidentiality.Confidentiality = "restricted"
	ta[taLowerConfidentiality.ID] = taLowerConfidentiality

	taHigherConfidentiality := createDefaultTechnicalAsset()
	taHigherConfidentiality.Confidentiality = "confidential"
	ta[taLowerConfidentiality.ID] = taHigherConfidentiality

	parsedModel, err := ParseModel(createInputModel(ta), map[string]risks.RiskRule{}, map[string]*CustomRisk{})

	assert.NoError(t, err)
	assert.Equal(t, types.Confidential, parsedModel.TechnicalAssets[taUndefinedConfidentiality.ID].Confidentiality)
	assert.Equal(t, types.Confidential, parsedModel.TechnicalAssets[taLowerConfidentiality.ID].Confidentiality)
	assert.Equal(t, types.Confidential, parsedModel.TechnicalAssets[taHigherConfidentiality.ID].Confidentiality)
}

func TestInferIntegrity_NotSet_NoOthers_ExpectTODO(t *testing.T) {
	ta := map[string]input.TechnicalAsset{}

	taUndefinedIntegrity := createDefaultTechnicalAsset()
	taUndefinedIntegrity.Integrity = ""
	ta[taUndefinedIntegrity.ID] = taUndefinedIntegrity

	parsedModel, err := ParseModel(createInputModel(ta), map[string]risks.RiskRule{}, map[string]*CustomRisk{})

	assert.NoError(t, err)
	// TODO: rename test and check if everyone agree that by default it should be archive if there are no other assets
	assert.Equal(t, types.Archive, parsedModel.TechnicalAssets[taUndefinedIntegrity.ID].Integrity)
}

func TestInferIntegrity_NotSet_ExpectHighestIntegrity(t *testing.T) {
	ta := map[string]input.TechnicalAsset{}

	taUndefinedIntegrity := createDefaultTechnicalAsset()
	taUndefinedIntegrity.Integrity = ""
	ta[taUndefinedIntegrity.ID] = taUndefinedIntegrity

	taLowerIntegrity := createDefaultTechnicalAsset()
	taLowerIntegrity.Integrity = "important"
	ta[taLowerIntegrity.ID] = taLowerIntegrity

	taHigherConfidentiality := createDefaultTechnicalAsset()
	taHigherConfidentiality.Confidentiality = "critical"
	ta[taHigherConfidentiality.ID] = taHigherConfidentiality

	parsedModel, err := ParseModel(createInputModel(ta), map[string]risks.RiskRule{}, map[string]*CustomRisk{})

	assert.NoError(t, err)
	assert.Equal(t, types.Critical, parsedModel.TechnicalAssets[taUndefinedIntegrity.ID].Integrity)
	assert.Equal(t, types.Important, parsedModel.TechnicalAssets[taLowerIntegrity.ID].Integrity)
	assert.Equal(t, types.Critical, parsedModel.TechnicalAssets[taHigherConfidentiality.ID].Integrity)
}

func TestInferAvailability_NotSet_NoOthers_ExpectTODO(t *testing.T) {
	ta := map[string]input.TechnicalAsset{}

	taUndefinedIntegrity := createDefaultTechnicalAsset()
	taUndefinedIntegrity.Integrity = ""
	ta[taUndefinedIntegrity.ID] = taUndefinedIntegrity

	parsedModel, err := ParseModel(createInputModel(ta), map[string]risks.RiskRule{}, map[string]*CustomRisk{})

	assert.NoError(t, err)
	assert.Equal(t, types.Archive, parsedModel.TechnicalAssets[taUndefinedIntegrity.ID].Integrity)
}

func TestInferAvailability_NotSet_ExpectHighestAvailability(t *testing.T) {
	ta := map[string]input.TechnicalAsset{}

	taUndefinedAvailability := createDefaultTechnicalAsset()
	taUndefinedAvailability.Availability = ""
	ta[taUndefinedAvailability.ID] = taUndefinedAvailability

	taLowerAvailability := createDefaultTechnicalAsset()
	taLowerAvailability.Availability = "important"
	ta[taLowerAvailability.ID] = taLowerAvailability

	taHigherAvailability := createDefaultTechnicalAsset()
	taHigherAvailability.Availability = "critical"
	ta[taHigherAvailability.ID] = taHigherAvailability

	parsedModel, err := ParseModel(createInputModel(ta), map[string]risks.RiskRule{}, map[string]*CustomRisk{})

	assert.NoError(t, err)
	assert.Equal(t, types.Critical, parsedModel.TechnicalAssets[taUndefinedAvailability.ID].Availability)
	assert.Equal(t, types.Important, parsedModel.TechnicalAssets[taLowerAvailability.ID].Availability)
	assert.Equal(t, types.Critical, parsedModel.TechnicalAssets[taHigherAvailability.ID].Availability)
}

func createInputModel(technicalAssets map[string]input.TechnicalAsset) *input.Model {
	return &input.Model{
		TechnicalAssets: technicalAssets,

		// set some dummy values to bypass validation
		BusinessCriticality: "archive",
	}
}

func createDefaultTechnicalAsset() input.TechnicalAsset {
	return input.TechnicalAsset{
		ID: uuid.New().String(),
		// those values are required to bypass validation
		Usage:           "business",
		Type:            "process",
		Size:            "system",
		Technology:      "unknown-technology",
		Encryption:      "none",
		Machine:         "virtual",
		Confidentiality: "public",
		Integrity:       "archive",
		Availability:    "archive",
	}
}
