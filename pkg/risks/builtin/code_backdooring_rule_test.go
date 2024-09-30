package builtin

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestCodeBackdooringRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewCodeBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCodeBackdooringRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewCodeBackdooringRule()

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

func TestCodeBackdooringRuleGenerateRisksTechAssetNotContainSecretsNotRisksCreated(t *testing.T) {
	rule := NewCodeBackdooringRule()

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

func TestCodeBackdooringRuleGenerateRisksTechAssetFromInternetRisksCreated(t *testing.T) {
	rule := NewCodeBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"git-lab-ci-cd": {
				Title:    "GitLab CI/CD",
				Internet: true,
				Technologies: types.TechnologyList{
					{
						Name: "build-pipeline",
						Attributes: map[string]bool{
							types.IsDevelopmentRelevant: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Code Backdooring</b> risk at <b>GitLab CI/CD</b>", risks[0].Title)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestCodeBackdooringRuleGenerateRisksTechAssetProcessConfidentialityRisksCreated(t *testing.T) {
	rule := NewCodeBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"git-lab-ci-cd": {
				Title:    "GitLab CI/CD",
				Internet: true,
				Technologies: types.TechnologyList{
					{
						Name: "build-pipeline",
						Attributes: map[string]bool{
							types.IsDevelopmentRelevant: true,
						},
					},
				},
				DataAssetsProcessed: []string{"critical-data-asset"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"critical-data-asset": {
				Integrity: types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Code Backdooring</b> risk at <b>GitLab CI/CD</b>", risks[0].Title)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}

func TestCodeBackdoogingRuleGenerateRisksTechAssetNotInternetButNotComingThroughVPNInternetRisksCreated(t *testing.T) {
	rule := NewCodeBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"git-lab-ci-cd": {
				Id:    "git-lab-ci-cd",
				Title: "GitLab CI/CD",
				Technologies: types.TechnologyList{
					{
						Name: "build-pipeline",
						Attributes: map[string]bool{
							types.IsDevelopmentRelevant: true,
						},
					},
				},
			},
			"reverse-proxy": {
				Title:    "Reverse Proxy",
				Internet: true,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"git-lab-ci-cd": {
				{
					SourceId: "reverse-proxy",
					TargetId: "git-lab-ci-cd",
					VPN:      false,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Code Backdooring</b> risk at <b>GitLab CI/CD</b>", risks[0].Title)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestCodeBackdooringRuleGenerateRisksTechAssetNotInternetButComingThroughVPNNoInternetRisksNotCreated(t *testing.T) {
	rule := NewCodeBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"git-lab-ci-cd": {
				Id:    "git-lab-ci-cd",
				Title: "GitLab CI/CD",
				Technologies: types.TechnologyList{
					{
						Name: "build-pipeline",
						Attributes: map[string]bool{
							types.IsDevelopmentRelevant: true,
						},
					},
				},
			},
			"vpn": {
				Title: "VPN",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"git-lab-ci-cd": {
				{
					SourceId: "vpn",
					TargetId: "git-lab-ci-cd",
					VPN:      true,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCodeBackdooringRuleGenerateRisksTechAssetNotInternetButComingThroughVPNInternetButOutOfScopeRisksNotCreated(t *testing.T) {
	rule := NewCodeBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"git-lab-ci-cd": {
				Id:         "git-lab-ci-cd",
				Title:      "GitLab CI/CD",
				OutOfScope: true,
				Technologies: types.TechnologyList{
					{
						Name: "build-pipeline",
						Attributes: map[string]bool{
							types.IsDevelopmentRelevant: true,
						},
					},
				},
			},
			"vpn": {
				Title:    "VPN",
				Internet: true,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"git-lab-ci-cd": {
				{
					SourceId: "vpn",
					TargetId: "git-lab-ci-cd",
					VPN:      true,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCodeBackdoogingRuleGenerateRisksNotImportantDataAssetNoAddingTargetRisksCreated(t *testing.T) {
	rule := NewCodeBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"git-lab-ci-cd": {
				Id:    "git-lab-ci-cd",
				Title: "GitLab CI/CD",
				Technologies: types.TechnologyList{
					{
						Name: "build-pipeline",
						Attributes: map[string]bool{
							types.IsDevelopmentRelevant: true,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						Usage:          types.DevOps,
						DataAssetsSent: []string{"not-important-data-asset"},
						TargetId:       "deployment-target",
						SourceId:       "git-lab-ci-cd",
					},
				},
			},
			"reverse-proxy": {
				Id:       "reverse-proxy",
				Title:    "Reverse Proxy",
				Internet: true,
			},
			"deployment-target": {
				Id:    "deployment-target",
				Title: "Deployment Target",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"git-lab-ci-cd": {
				{
					SourceId: "reverse-proxy",
					TargetId: "git-lab-ci-cd",
					VPN:      false,
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"not-important-data-asset": {
				Integrity: types.Operational,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Code Backdooring</b> risk at <b>GitLab CI/CD</b>", risks[0].Title)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, []string{"git-lab-ci-cd"}, risks[0].DataBreachTechnicalAssetIDs)
}

func TestCodeBackdoogingRuleGenerateRisksNotDevOpsDataAssetNoAddingTargetRisksCreated(t *testing.T) {
	rule := NewCodeBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"git-lab-ci-cd": {
				Id:    "git-lab-ci-cd",
				Title: "GitLab CI/CD",
				Technologies: types.TechnologyList{
					{
						Name: "build-pipeline",
						Attributes: map[string]bool{
							types.IsDevelopmentRelevant: true,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						Usage:          types.Business,
						DataAssetsSent: []string{"important-data-asset"},
						TargetId:       "deployment-target",
						SourceId:       "git-lab-ci-cd",
					},
				},
			},
			"reverse-proxy": {
				Id:       "reverse-proxy",
				Title:    "Reverse Proxy",
				Internet: true,
			},
			"deployment-target": {
				Id:    "deployment-target",
				Title: "Deployment Target",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"git-lab-ci-cd": {
				{
					SourceId: "reverse-proxy",
					TargetId: "git-lab-ci-cd",
					VPN:      false,
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"important-data-asset": {
				Integrity: types.Important,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Code Backdooring</b> risk at <b>GitLab CI/CD</b>", risks[0].Title)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, []string{"git-lab-ci-cd"}, risks[0].DataBreachTechnicalAssetIDs)
}

func TestCodeBackdoogingRuleGenerateRisksDevOpsImportantDataAssetNoAddingTargetRisksCreated(t *testing.T) {
	rule := NewCodeBackdooringRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"git-lab-ci-cd": {
				Id:    "git-lab-ci-cd",
				Title: "GitLab CI/CD",
				Technologies: types.TechnologyList{
					{
						Name: "build-pipeline",
						Attributes: map[string]bool{
							types.IsDevelopmentRelevant: true,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						Usage:          types.DevOps,
						DataAssetsSent: []string{"important-data-asset"},
						TargetId:       "deployment-target",
						SourceId:       "git-lab-ci-cd",
					},
				},
			},
			"reverse-proxy": {
				Id:       "reverse-proxy",
				Title:    "Reverse Proxy",
				Internet: true,
			},
			"deployment-target": {
				Id:    "deployment-target",
				Title: "Deployment Target",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"git-lab-ci-cd": {
				{
					SourceId: "reverse-proxy",
					TargetId: "git-lab-ci-cd",
					VPN:      false,
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"important-data-asset": {
				Integrity: types.Important,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Code Backdooring</b> risk at <b>GitLab CI/CD</b>", risks[0].Title)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	orderedDataBreachTechnicalAssetIDs := risks[0].DataBreachTechnicalAssetIDs
	sort.Strings(orderedDataBreachTechnicalAssetIDs)
	assert.Equal(t, []string{"deployment-target", "git-lab-ci-cd"}, orderedDataBreachTechnicalAssetIDs)
}
