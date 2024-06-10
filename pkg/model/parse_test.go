/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package model

import (
	"testing"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

func TestDefaultInputNotFail(t *testing.T) {
	parsedModel, err := ParseModel(&mockConfig{}, createInputModel(make(map[string]input.TechnicalAsset), make(map[string]input.DataAsset)), make(types.RiskRules), make(types.RiskRules))

	assert.NoError(t, err)
	assert.NotNil(t, parsedModel)
}

func TestInferConfidentiality_NotSet_NoOthers_ExpectTODO(t *testing.T) {
	ta := make(map[string]input.TechnicalAsset)
	da := make(map[string]input.DataAsset)

	_, err := ParseModel(&mockConfig{}, createInputModel(ta, da), make(types.RiskRules), make(types.RiskRules))
	// TODO: rename test and check if everyone agree that by default it should be public if there are no other assets

	assert.NoError(t, err)
}

func TestInferConfidentiality_ExpectHighestConfidentiality(t *testing.T) {
	ta := make(map[string]input.TechnicalAsset)
	da := make(map[string]input.DataAsset)

	daConfidentialConfidentiality := createDataAsset(types.Confidential, types.Critical, types.Critical)
	da[daConfidentialConfidentiality.ID] = daConfidentialConfidentiality

	daRestrictedConfidentiality := createDataAsset(types.Restricted, types.Important, types.Important)
	da[daRestrictedConfidentiality.ID] = daRestrictedConfidentiality

	daPublicConfidentiality := createDataAsset(types.Public, types.Archive, types.Archive)
	da[daPublicConfidentiality.ID] = daPublicConfidentiality

	taWithConfidentialConfidentialityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithConfidentialConfidentialityDataAsset.DataAssetsProcessed = append(taWithConfidentialConfidentialityDataAsset.DataAssetsProcessed, daConfidentialConfidentiality.ID)
	ta[taWithConfidentialConfidentialityDataAsset.ID] = taWithConfidentialConfidentialityDataAsset

	taWithRestrictedConfidentialityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithRestrictedConfidentialityDataAsset.DataAssetsProcessed = append(taWithRestrictedConfidentialityDataAsset.DataAssetsProcessed, daRestrictedConfidentiality.ID)
	ta[taWithRestrictedConfidentialityDataAsset.ID] = taWithRestrictedConfidentialityDataAsset

	taWithPublicConfidentialityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithPublicConfidentialityDataAsset.DataAssetsProcessed = append(taWithPublicConfidentialityDataAsset.DataAssetsProcessed, daPublicConfidentiality.ID)
	ta[taWithPublicConfidentialityDataAsset.ID] = taWithPublicConfidentialityDataAsset

	parsedModel, err := ParseModel(&mockConfig{}, createInputModel(ta, da), make(types.RiskRules), make(types.RiskRules))

	assert.NoError(t, err)
	assert.Equal(t, types.Confidential, parsedModel.TechnicalAssets[taWithConfidentialConfidentialityDataAsset.ID].Confidentiality)
	assert.Equal(t, types.Restricted, parsedModel.TechnicalAssets[taWithRestrictedConfidentialityDataAsset.ID].Confidentiality)
	assert.Equal(t, types.Internal, parsedModel.TechnicalAssets[taWithPublicConfidentialityDataAsset.ID].Confidentiality)
}

func TestInferIntegrity_NotSet_NoOthers_ExpectTODO(t *testing.T) {
	ta := make(map[string]input.TechnicalAsset)
	da := make(map[string]input.DataAsset)

	_, err := ParseModel(&mockConfig{}, createInputModel(ta, da), make(types.RiskRules), make(types.RiskRules))
	// TODO: rename test and check if everyone agree that by default it should be public if there are no other assets

	assert.NoError(t, err)
}

func TestInferIntegrity_ExpectHighestIntegrity(t *testing.T) {
	ta := make(map[string]input.TechnicalAsset)
	da := make(map[string]input.DataAsset)

	daCriticalIntegrity := createDataAsset(types.Confidential, types.Critical, types.Critical)
	da[daCriticalIntegrity.ID] = daCriticalIntegrity

	daImportantIntegrity := createDataAsset(types.Restricted, types.Important, types.Important)
	da[daImportantIntegrity.ID] = daImportantIntegrity

	daArchiveIntegrity := createDataAsset(types.Public, types.Archive, types.Archive)
	da[daArchiveIntegrity.ID] = daArchiveIntegrity

	taWithCriticalIntegrityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithCriticalIntegrityDataAsset.DataAssetsProcessed = append(taWithCriticalIntegrityDataAsset.DataAssetsProcessed, daCriticalIntegrity.ID)
	ta[taWithCriticalIntegrityDataAsset.ID] = taWithCriticalIntegrityDataAsset

	taWithImportantIntegrityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithImportantIntegrityDataAsset.DataAssetsProcessed = append(taWithImportantIntegrityDataAsset.DataAssetsProcessed, daImportantIntegrity.ID)
	ta[taWithImportantIntegrityDataAsset.ID] = taWithImportantIntegrityDataAsset

	taWithArchiveIntegrityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithArchiveIntegrityDataAsset.DataAssetsProcessed = append(taWithArchiveIntegrityDataAsset.DataAssetsProcessed, daArchiveIntegrity.ID)
	ta[taWithArchiveIntegrityDataAsset.ID] = taWithArchiveIntegrityDataAsset

	parsedModel, err := ParseModel(&mockConfig{}, createInputModel(ta, da), make(types.RiskRules), make(types.RiskRules))

	assert.NoError(t, err)
	assert.Equal(t, types.Critical, parsedModel.TechnicalAssets[taWithCriticalIntegrityDataAsset.ID].Integrity)
	assert.Equal(t, types.Important, parsedModel.TechnicalAssets[taWithImportantIntegrityDataAsset.ID].Integrity)
	assert.Equal(t, types.Operational, parsedModel.TechnicalAssets[taWithArchiveIntegrityDataAsset.ID].Integrity)
}

func TestInferAvailability_NotSet_NoOthers_ExpectTODO(t *testing.T) {
	ta := make(map[string]input.TechnicalAsset)
	da := make(map[string]input.DataAsset)

	_, err := ParseModel(&mockConfig{}, createInputModel(ta, da), make(types.RiskRules), make(types.RiskRules))

	assert.NoError(t, err)
}

func TestInferAvailability_ExpectHighestAvailability(t *testing.T) {
	ta := make(map[string]input.TechnicalAsset)
	da := make(map[string]input.DataAsset)

	daCriticalAvailability := createDataAsset(types.Confidential, types.Critical, types.Critical)
	da[daCriticalAvailability.ID] = daCriticalAvailability

	daImportantAvailability := createDataAsset(types.Restricted, types.Important, types.Important)
	da[daImportantAvailability.ID] = daImportantAvailability

	daArchiveAvailability := createDataAsset(types.Public, types.Archive, types.Archive)
	da[daArchiveAvailability.ID] = daArchiveAvailability

	taWithCriticalAvailabilityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithCriticalAvailabilityDataAsset.DataAssetsProcessed = append(taWithCriticalAvailabilityDataAsset.DataAssetsProcessed, daCriticalAvailability.ID)
	ta[taWithCriticalAvailabilityDataAsset.ID] = taWithCriticalAvailabilityDataAsset

	taWithImportantAvailabilityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithImportantAvailabilityDataAsset.DataAssetsProcessed = append(taWithImportantAvailabilityDataAsset.DataAssetsProcessed, daImportantAvailability.ID)
	ta[taWithImportantAvailabilityDataAsset.ID] = taWithImportantAvailabilityDataAsset

	taWithArchiveAvailabilityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithArchiveAvailabilityDataAsset.DataAssetsProcessed = append(taWithArchiveAvailabilityDataAsset.DataAssetsProcessed, daArchiveAvailability.ID)
	ta[taWithArchiveAvailabilityDataAsset.ID] = taWithArchiveAvailabilityDataAsset

	parsedModel, err := ParseModel(&mockConfig{}, createInputModel(ta, da), make(types.RiskRules), make(types.RiskRules))

	assert.NoError(t, err)
	assert.Equal(t, types.Critical, parsedModel.TechnicalAssets[taWithCriticalAvailabilityDataAsset.ID].Availability)
	assert.Equal(t, types.Important, parsedModel.TechnicalAssets[taWithImportantAvailabilityDataAsset.ID].Availability)
	assert.Equal(t, types.Operational, parsedModel.TechnicalAssets[taWithArchiveAvailabilityDataAsset.ID].Availability)
}

func createInputModel(technicalAssets map[string]input.TechnicalAsset, dataAssets map[string]input.DataAsset) *input.Model {
	return &input.Model{
		TechnicalAssets: technicalAssets,
		DataAssets:      dataAssets,

		// set some dummy values to bypass validation
		BusinessCriticality: "archive",
	}
}

func createTechnicalAsset(confidentiality types.Confidentiality, integrity types.Criticality, availability types.Criticality) input.TechnicalAsset {
	return input.TechnicalAsset{
		ID: uuid.New().String(),
		// those values are required to bypass validation
		Usage:           "business",
		Type:            "process",
		Size:            "system",
		Technology:      "unknown-technology",
		Encryption:      "none",
		Machine:         "virtual",
		Confidentiality: confidentiality.String(),
		Integrity:       integrity.String(),
		Availability:    availability.String(),
	}
}

func createDataAsset(confidentiality types.Confidentiality, integrity types.Criticality, availability types.Criticality) input.DataAsset {
	return input.DataAsset{
		ID:              uuid.New().String(),
		Usage:           "business",
		Quantity:        "few",
		Confidentiality: confidentiality.String(),
		Integrity:       integrity.String(),
		Availability:    availability.String(),
	}
}

type mockConfig struct {
}

func (m *mockConfig) GetAppFolder() string {
	return ""
}

func (m *mockConfig) GetTechnologyFilename() string {
	return ""
}
