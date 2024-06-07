package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestUnnecessaryTechnicalAssetRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryTechnicalAssetRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryTechnicalAssetRuleGenerateRisksNoDataProcessedOrStoreNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryTechnicalAssetRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:               "Technical Asset",
				Id:                  "ta1",
				DataAssetsProcessed: []string{},
				DataAssetsStored:    []string{},
				CommunicationLinks:  []*types.CommunicationLink{},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unnecessary Technical Asset</b> named <b>Technical Asset</b>", risks[0].Title)
}

func TestUnnecessaryTechnicalAssetRuleSomeDataStoredAndSomeOutgoingCommunicationNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryTechnicalAssetRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:               "First Technical Asset",
				Id:                  "ta1",
				DataAssetsProcessed: []string{},
				DataAssetsStored:    []string{"data"},
				CommunicationLinks: []*types.CommunicationLink{
					{
						DataAssetsSent: []string{"data"},
						TargetId:       "ta2",
						SourceId:       "ta1",
					},
				},
			},
			"ta2": {
				Title:               "Second Technical Asset",
				Id:                  "ta2",
				DataAssetsProcessed: []string{"data"},
				DataAssetsStored:    []string{},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"data": {
				Id:    "data",
				Title: "data",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta2": {
				{
					DataAssetsReceived: []string{"data"},
					TargetId:           "ta1",
					SourceId:           "ta2",
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}
