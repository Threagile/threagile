package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestIncompleteModelRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewIncompleteModelRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestIncompleteModelRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewIncompleteModelRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestIncompleteModelRuleGenerateRisksTechnicalAssetWithKnownTechnologiesAndWithoutCommunicationLinksNoRisksCreated(t *testing.T) {
	rule := NewIncompleteModelRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "Test Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.UnknownTechnology: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestIncompleteModelRuleGenerateRisksTechnicalAssetContainTechnologyWithoutAttributesRisksCreated(t *testing.T) {
	rule := NewIncompleteModelRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "Test Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "tool",
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unknown Technology</b> specified at technical asset <b>Test Technical Asset</b>", risks[0].Title)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}

func TestIncompleteModelRuleGenerateRisksTechnicalAssetContainUnknownTechnologiesRisksCreated(t *testing.T) {
	rule := NewIncompleteModelRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "Test Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "unknown",
						Attributes: map[string]bool{
							types.UnknownTechnology: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unknown Technology</b> specified at technical asset <b>Test Technical Asset</b>", risks[0].Title)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}

func TestIncompleteModelRuleGenerateRisksNoTechnologySpecifiedRisksCreated(t *testing.T) {
	rule := NewIncompleteModelRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:        "Test Technical Asset",
				Technologies: types.TechnologyList{},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unknown Technology</b> specified at technical asset <b>Test Technical Asset</b>", risks[0].Title)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}

func TestIncompleteModelRuleGenerateRisksKnownProtocolCommunicationLinksNoRisksCreated(t *testing.T) {
	rule := NewIncompleteModelRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "Test Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.UnknownTechnology: false,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						Title:    "Test Communication Link",
						Protocol: types.HTTPS,
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestIncompleteModelRuleGenerateRisksUnknownProtocolCommunicationLinksRisksCreated(t *testing.T) {
	rule := NewIncompleteModelRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "Test Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.UnknownTechnology: false,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						Title:    "Test Communication Link",
						Protocol: types.UnknownProtocol,
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Unknown Protocol</b> specified for communication link <b>Test Communication Link</b> at technical asset <b>Test Technical Asset</b>", risks[0].Title)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}
