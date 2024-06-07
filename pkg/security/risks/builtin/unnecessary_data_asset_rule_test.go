package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
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
