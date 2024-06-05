package scripts

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/script"
	"github.com/threagile/threagile/pkg/security/types"
)

// TODO: fix when there are no technical assets in scope
// func TestAccidentalSecretLeakRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
// 	rule := loadAccidentalSecretLeakRule()

// 	risks, err := rule.GenerateRisks(&types.Model{})

// 	assert.Nil(t, err)
// 	assert.Empty(t, risks)
// }

func TestAccidentalSecretLeakRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := loadAccidentalSecretLeakRule()

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

func TestAccidentalSecretLeakRuleGenerateRisksTechAssetNotContainSecretsNotRisksCreated(t *testing.T) {
	rule := loadAccidentalSecretLeakRule()

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

// TODO: fix the test
// func TestAccidentalSecretLeakRuleGenerateRisksTechAssetGitContainSecretsRisksCreated(t *testing.T) {
// 	rule := loadAccidentalSecretLeakRule()

// 	risks, err := rule.GenerateRisks(&types.Model{
// 		TechnicalAssets: map[string]*types.TechnicalAsset{
// 			"ta1": {
// 				Technologies: types.TechnologyList{
// 					{
// 						Name: "git repository",
// 						Attributes: map[string]bool{
// 							types.MayContainSecrets: true,
// 						},
// 					},
// 				},
// 				Tags: []string{"git"},
// 			},
// 		},
// 	})

// 	assert.Nil(t, err)
// 	assert.Equal(t, len(risks), 1)
// 	assert.Contains(t, risks[0].Title, "Accidental Secret Leak (Git)")
// }

// TODO: fix the test
// func TestAccidentalSecretLeakRuleGenerateRisksTechAssetNotGitContainSecretsRisksCreated(t *testing.T) {
// 	rule := loadAccidentalSecretLeakRule()

// 	risks, err := rule.GenerateRisks(&types.Model{
// 		TechnicalAssets: map[string]*types.TechnicalAsset{
// 			"ta1": {
// 				Technologies: types.TechnologyList{
// 					{
// 						Name: "git repository",
// 						Attributes: map[string]bool{
// 							types.MayContainSecrets: true,
// 						},
// 					},
// 				},
// 			},
// 		},
// 	})

// 	assert.Nil(t, err)
// 	assert.Equal(t, len(risks), 1)
// 	assert.Equal(t, "<b>Accidental Secret Leak</b> risk at <b></b>", risks[0].Title)
// }

// TODO: fix the test
// func TestAccidentalSecretLeakRuleGenerateRisksTechAssetProcessStrictlyConfidentialDataAssetHighImpactRiskCreated(t *testing.T) {
// 	rule := loadAccidentalSecretLeakRule()

// 	risks, err := rule.GenerateRisks(&types.Model{
// 		TechnicalAssets: map[string]*types.TechnicalAsset{
// 			"ta1": {
// 				Technologies: types.TechnologyList{
// 					{
// 						Name: "git repository",
// 						Attributes: map[string]bool{
// 							types.MayContainSecrets: true,
// 						},
// 					},
// 				},
// 				DataAssetsProcessed: []string{"confidential-data-asset", "strictly-confidential-data-asset"},
// 			},
// 		},
// 		DataAssets: map[string]*types.DataAsset{
// 			"confidential-data-asset": {
// 				Confidentiality: types.Confidential,
// 			},
// 			"strictly-confidential-data-asset": {
// 				Confidentiality: types.StrictlyConfidential,
// 			},
// 		},
// 	})

// 	assert.Nil(t, err)
// 	assert.Equal(t, len(risks), 1)
// 	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
// }

//go:embed accidental-secret-leak.yaml
var accidental_secret_leak string

func loadAccidentalSecretLeakRule() types.RiskRule {
	result := new(script.RiskRule).Init()
	riskRule, _ := result.ParseFromData([]byte(accidental_secret_leak))
	return riskRule
}
