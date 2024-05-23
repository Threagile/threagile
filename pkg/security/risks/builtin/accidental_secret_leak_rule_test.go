package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewAccidentalSecretLeakRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewAccidentalSecretLeakRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				OutOfScope: true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestGenerateRisksTechAssetNotContainSecretsNotRisksCreated(t *testing.T) {
	rule := NewAccidentalSecretLeakRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.MayContainSecrets:                                 false,
							types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestGenerateRisksTechAssetGitContainSecretsRisksCreated(t *testing.T) {
	rule := NewAccidentalSecretLeakRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Technologies: types.TechnologyList{
					{
						Name: "git repository",
						Attributes: map[string]bool{
							types.MayContainSecrets: true,
						},
					},
				},
				Tags: []string{"git"},
			},
		},
	})

	assert.Nil(t, err)
	assert.Equal(t, len(risks), 1)
	assert.Contains(t, risks[0].Title, "Accidental Secret Leak (Git)")
}

func TestGenerateRisksTechAssetNotGitContainSecretsRisksCreated(t *testing.T) {
	rule := NewAccidentalSecretLeakRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Technologies: types.TechnologyList{
					{
						Name: "git repository",
						Attributes: map[string]bool{
							types.MayContainSecrets: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Equal(t, len(risks), 1)
	assert.Equal(t, "<b>Accidental Secret Leak</b> risk at <b></b>", risks[0].Title)
}

func TestGenerateRisksTechAssetProcessStrictlyConfidentialDataAssetHighImpactRiskCreated(t *testing.T) {
	rule := NewAccidentalSecretLeakRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Technologies: types.TechnologyList{
					{
						Name: "git repository",
						Attributes: map[string]bool{
							types.MayContainSecrets: true,
						},
					},
				},
				DataAssetsProcessed: []string{"confidential-data-asset", "strictly-confidential-data-asset"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"confidential-data-asset": {
				Confidentiality: types.Confidential,
			},
			"strictly-confidential-data-asset": {
				Confidentiality: types.StrictlyConfidential,
			},
		},
	})

	assert.Nil(t, err)
	assert.Equal(t, len(risks), 1)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}
