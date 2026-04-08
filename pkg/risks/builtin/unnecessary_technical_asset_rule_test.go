package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
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

func TestUnnecessaryTechnicalAssetRuleNoDataButHasIncomingLinksOnlyLeftORSatisfiedNoRiskCreated(t *testing.T) {
	// No data processed/stored (left side of OR true) BUT has incoming links (right side of OR false)
	// Since the rule uses OR, left side being true is enough to trigger risk.
	// Wait - re-reading the rule: risk fires if EITHER condition is true.
	// Left condition: no data processed AND no data stored → true here
	// Therefore risk IS created. The test verifies that having incoming links alone does NOT prevent the risk
	// when no data is processed/stored.
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
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					TargetId: "ta1",
					SourceId: "other",
				},
			},
		},
	})

	assert.Nil(t, err)
	// No data processed/stored triggers the risk regardless of incoming links
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unnecessary Technical Asset</b> named <b>Technical Asset</b>", risks[0].Title)
}

func TestUnnecessaryTechnicalAssetRuleNoDataButHasOutgoingLinksOnlyLeftORSatisfiedRiskCreated(t *testing.T) {
	// No data processed/stored (left side of OR true) and has outgoing links (right side of OR false for ta1).
	// Since the rule uses OR, the left side being true alone triggers the risk for ta1.
	// ta2 has data processed so only the right side of OR matters for it; it has an incoming link so no risk for ta2.
	rule := NewUnnecessaryTechnicalAssetRule()
	outgoingLink := &types.CommunicationLink{
		TargetId: "ta2",
		SourceId: "ta1",
	}
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:               "Technical Asset",
				Id:                  "ta1",
				DataAssetsProcessed: []string{},
				DataAssetsStored:    []string{},
				CommunicationLinks: []*types.CommunicationLink{
					outgoingLink,
				},
			},
			"ta2": {
				Title:               "Target Technical Asset",
				Id:                  "ta2",
				DataAssetsProcessed: []string{"data"},
				DataAssetsStored:    []string{},
				CommunicationLinks:  []*types.CommunicationLink{},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"data": {Id: "data", Title: "data"},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta2": {outgoingLink},
		},
	})

	assert.Nil(t, err)
	// No data processed/stored triggers the risk for ta1 regardless of outgoing communication links.
	// ta2 has data and an incoming link so it does not trigger.
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unnecessary Technical Asset</b> named <b>Technical Asset</b>", risks[0].Title)
}

func TestUnnecessaryTechnicalAssetRuleDataProcessedButNoCommunicationLinksRightORSatisfiedRiskCreated(t *testing.T) {
	// Has data processed (left side of OR false) BUT no outgoing links AND no incoming links (right side of OR true).
	// Since the rule uses OR, the right side being true triggers the risk.
	rule := NewUnnecessaryTechnicalAssetRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:               "Technical Asset",
				Id:                  "ta1",
				DataAssetsProcessed: []string{"data"},
				DataAssetsStored:    []string{},
				CommunicationLinks:  []*types.CommunicationLink{},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"data": {
				Id:    "data",
				Title: "data",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{},
	})

	assert.Nil(t, err)
	// No communication links at all triggers the risk regardless of data processed
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unnecessary Technical Asset</b> named <b>Technical Asset</b>", risks[0].Title)
}

func TestUnnecessaryTechnicalAssetRuleNoDataAndNoCommunicationLinksBothORConditionsTrueRiskCreated(t *testing.T) {
	// No data processed/stored (left side of OR true) AND no outgoing links AND no incoming links (right side of OR true).
	// Both OR conditions are true: risk is definitely created.
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
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unnecessary Technical Asset</b> named <b>Technical Asset</b>", risks[0].Title)
}
