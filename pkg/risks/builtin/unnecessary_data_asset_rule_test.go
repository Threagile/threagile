package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestUnnecessaryDataAssetRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataAssetRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryDataAssetRuleGenerateRisksDataAssetRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataAssetRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id: "ta1",
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"data": {
				Id:    "data",
				Title: "data",
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unnecessary Data Asset</b> named <b>data</b>", risks[0].Title)
}

func TestUnnecessaryDataAssetRuleGenerateRisksDataAssetStoredNoRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataAssetRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:               "ta1",
				DataAssetsStored: []string{"data"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"data": {
				Id:    "data",
				Title: "data",
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryDataAssetRuleGenerateRisksDataAssetProcessedNoRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataAssetRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:                  "ta1",
				DataAssetsProcessed: []string{"data"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"data": {
				Id:    "data",
				Title: "data",
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryDataAssetRuleGenerateRisksDataAssetSentNoRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataAssetRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id: "ta1",
				CommunicationLinks: []*types.CommunicationLink{
					{
						TargetId:           "ta2",
						DataAssetsSent:     []string{"data"},
						DataAssetsReceived: []string{},
					},
				},
			},
			"ta2": {
				Id: "ta2",
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"data": {
				Id:    "data",
				Title: "data",
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryDataAssetRuleGenerateRisksDataAssetReceivedNoRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataAssetRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id: "ta1",
				CommunicationLinks: []*types.CommunicationLink{
					{
						TargetId:           "ta2",
						DataAssetsSent:     []string{},
						DataAssetsReceived: []string{"data"},
					},
				},
			},
			"ta2": {
				Id: "ta2",
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"data": {
				Id:    "data",
				Title: "data",
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryDataAssetRuleGenerateRisksMultipleDataAssetsOnlyUnusedOnesCreateRisks(t *testing.T) {
	rule := NewUnnecessaryDataAssetRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:                  "ta1",
				DataAssetsProcessed: []string{"used-data-1"},
				DataAssetsStored:    []string{"used-data-2"},
				CommunicationLinks: []*types.CommunicationLink{
					{
						TargetId:       "ta2",
						DataAssetsSent: []string{"used-data-3"},
					},
				},
			},
			"ta2": {
				Id: "ta2",
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"used-data-1": {
				Id:    "used-data-1",
				Title: "Used Data 1",
			},
			"used-data-2": {
				Id:    "used-data-2",
				Title: "Used Data 2",
			},
			"used-data-3": {
				Id:    "used-data-3",
				Title: "Used Data 3",
			},
			"unused-data-1": {
				Id:    "unused-data-1",
				Title: "Unused Data 1",
			},
			"unused-data-2": {
				Id:    "unused-data-2",
				Title: "Unused Data 2",
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 2)
	riskDataAssetIDs := []string{risks[0].MostRelevantDataAssetId, risks[1].MostRelevantDataAssetId}
	assert.Contains(t, riskDataAssetIDs, "unused-data-1")
	assert.Contains(t, riskDataAssetIDs, "unused-data-2")
}

func TestUnnecessaryDataAssetRuleGenerateRisksDataAssetUsedInMultipleTechnicalAssetsNoRiskCreated(t *testing.T) {
	rule := NewUnnecessaryDataAssetRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:                  "ta1",
				DataAssetsProcessed: []string{"shared-data"},
			},
			"ta2": {
				Id:               "ta2",
				DataAssetsStored: []string{"shared-data"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"shared-data": {
				Id:    "shared-data",
				Title: "Shared Data",
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryDataAssetRuleGenerateRisksUnusedDataAssetHasCorrectSyntheticId(t *testing.T) {
	rule := NewUnnecessaryDataAssetRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id: "ta1",
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"unused-data": {
				Id:    "unused-data",
				Title: "Unused Data",
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "unnecessary-data-asset@unused-data", risks[0].SyntheticId)
	assert.Equal(t, "unused-data", risks[0].MostRelevantDataAssetId)
}
