package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
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

func TestUnnecessaryCommunicationLinkRuleSourceInScopeTargetOutOfScopeNoDataRiskCreated(t *testing.T) {
	// Only BOTH assets out-of-scope skips the risk. Source in-scope + target out-of-scope → risk IS created.
	rule := NewUnnecessaryCommunicationLinkRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Source Asset",
				CommunicationLinks: []*types.CommunicationLink{
					{
						Id:       "link1",
						Title:    "Link To Out Of Scope",
						TargetId: "ta2",
					},
				},
				OutOfScope: false,
			},
			"ta2": {
				Id:         "ta2",
				Title:      "Target Asset",
				OutOfScope: true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unnecessary Communication Link</b> titled <b>Link To Out Of Scope</b> at technical asset <b>Source Asset</b>", risks[0].Title)
}

func TestUnnecessaryCommunicationLinkRuleSourceOutOfScopeTargetInScopeNoDataRiskCreated(t *testing.T) {
	// Only BOTH assets out-of-scope skips the risk. Source out-of-scope + target in-scope → risk IS created.
	rule := NewUnnecessaryCommunicationLinkRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Out Of Scope Source",
				CommunicationLinks: []*types.CommunicationLink{
					{
						Id:       "link1",
						Title:    "Link From Out Of Scope",
						TargetId: "ta2",
					},
				},
				OutOfScope: true,
			},
			"ta2": {
				Id:         "ta2",
				Title:      "In Scope Target",
				OutOfScope: false,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unnecessary Communication Link</b> titled <b>Link From Out Of Scope</b> at technical asset <b>Out Of Scope Source</b>", risks[0].Title)
}

func TestUnnecessaryCommunicationLinkRuleThreeLinksOneTwoWithDataOneWithoutExactlyOneRiskCreated(t *testing.T) {
	rule := NewUnnecessaryCommunicationLinkRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Source Asset",
				CommunicationLinks: []*types.CommunicationLink{
					{
						Id:             "link-with-sent",
						Title:          "Link With Sent Data",
						TargetId:       "ta2",
						DataAssetsSent: []string{"data"},
					},
					{
						Id:                 "link-with-received",
						Title:              "Link With Received Data",
						TargetId:           "ta2",
						DataAssetsReceived: []string{"data"},
					},
					{
						Id:       "link-without-data",
						Title:    "Link Without Data",
						TargetId: "ta2",
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Target Asset",
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"data": {
				Id:    "data",
				Title: "Data Asset",
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unnecessary Communication Link</b> titled <b>Link Without Data</b> at technical asset <b>Source Asset</b>", risks[0].Title)
}
