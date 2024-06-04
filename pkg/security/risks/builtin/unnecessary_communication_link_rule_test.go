package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestUnnecessaryCommunicationLinkRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryCommunicationLinkRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryCommunicationLinkRuleSomeDataSendNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryCommunicationLinkRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				CommunicationLinks: []*types.CommunicationLink{
					{
						Id:                 "ta1",
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
			"data": {},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryCommunicationLinkRuleSomeDataReceivedNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryCommunicationLinkRule()
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
			"data": {},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryCommunicationLinkRuleBothTechnicalAssetsOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryCommunicationLinkRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id: "ta1",
				CommunicationLinks: []*types.CommunicationLink{
					{
						TargetId: "ta2",
					},
				},
				OutOfScope: true,
			},
			"ta2": {
				Id:         "ta2",
				OutOfScope: true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryCommnuicationLinkRuleRisksCreated(t *testing.T) {
	rule := NewUnnecessaryCommunicationLinkRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Test technical asset",
				CommunicationLinks: []*types.CommunicationLink{{
					Title:    "Test communication link",
					TargetId: "ta2",
				},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Second test technical asset",
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Unnecessary Communication Link</b> titled <b>Test communication link</b> at technical asset <b>Test technical asset</b>", risks[0].Title)
}
