package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestMissingBuildInfrastructureRuleGenerateRisksEmptyModelNoRisksCreated(t *testing.T) {
	rule := NewMissingBuildInfrastructureRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingBuildInfrastructureRuleGenerateRisksCustomDevelopedPartOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewMissingBuildInfrastructureRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				OutOfScope:           true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingBuildInfrastructureRuleGenerateRisksCustomDevelopedPartWithoutBuildInfrastructureRiskCreated(t *testing.T) {
	rule := NewMissingBuildInfrastructureRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				OutOfScope: 		 false,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>Test Technical Asset</b> as an example)", risks[0].Title)
}

func TestMissingBuildInfrastructureRuleGenerateRisksCustomDevelopedPartWithBuildPipelineRiskCreated(t *testing.T) {
	rule := NewMissingBuildInfrastructureRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				OutOfScope: 		 false,
			},
			"ArgoCD": {
				Technologies: types.TechnologyList{
					{
						Name: "build-pipeline",
						Attributes: map[string]bool{
							types.BuildPipeline: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>Test Technical Asset</b> as an example)", risks[0].Title)
}

func TestMissingBuildInfrastructureRuleGenerateRisksCustomDevelopedPartWithBuildPipelineAndSourceCodeRepoRiskCreated(t *testing.T) {
	rule := NewMissingBuildInfrastructureRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
			},
			"ArgoCD": {
				Technologies: types.TechnologyList{
					{
						Name: "build-pipeline",
						Attributes: map[string]bool{
							types.BuildPipeline: true,
						},
					},
				},
			},
			"GitLab": {
				Technologies: types.TechnologyList{
					{
						Name: "source-code-repository",
						Attributes: map[string]bool{
							types.SourcecodeRepository: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>Test Technical Asset</b> as an example)", risks[0].Title)
}

func TestMissingBuildInfrastructureRuleGenerateRisksCustomDevelopedPartWithBuildPipelineAndSourceCodeRepoAndDevOpsClientNoRiskCreated(t *testing.T) {
	rule := NewMissingBuildInfrastructureRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
			},
			"ArgoCD": {
				Technologies: types.TechnologyList{
					{
						Name: "build-pipeline",
						Attributes: map[string]bool{
							types.BuildPipeline: true,
						},
					},
				},
			},
			"GitLab": {
				Technologies: types.TechnologyList{
					{
						Name: "source-code-repository",
						Attributes: map[string]bool{
							types.SourcecodeRepository: true,
						},
					},
				},
			},
			"DevOpsClient": {
				Technologies: types.TechnologyList{
					{
						Name: "source-code-repository",
						Attributes: map[string]bool{
							types.DevOpsClient: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingBuildInfrastructureRuleGenerateRisksProcessingConfidentialDataRisksCreatedWithMediumImpact(t *testing.T) {
	rule := NewMissingBuildInfrastructureRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				DataAssetsProcessed:  []string{"da1"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Title:           "Test Data Asset",
				Confidentiality: types.Confidential,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>Test Technical Asset</b> as an example)", risks[0].Title)
}

func TestMissingBuildInfrastructureRuleGenerateRisksProcessingCriticalIntegrityDataRisksCreatedWithMediumImpact(t *testing.T) {
	rule := NewMissingBuildInfrastructureRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				DataAssetsProcessed:  []string{"da1"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Title:     "Test Data Asset",
				Integrity: types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>Test Technical Asset</b> as an example)", risks[0].Title)
}

func TestMissingBuildInfrastructureRuleGenerateRisksProcessingCriticalAvailabilityDataRisksCreatedWithMediumImpact(t *testing.T) {
	rule := NewMissingBuildInfrastructureRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				DataAssetsProcessed:  []string{"da1"},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Title:        "Test Data Asset",
				Availability: types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>Test Technical Asset</b> as an example)", risks[0].Title)
}

func TestMissingBuildInfrastructureRuleGenerateRisksConfidentialTechnicalAssetRisksCreatedWithMediumImpact(t *testing.T) {
	rule := NewMissingBuildInfrastructureRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				Confidentiality:      types.Confidential,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>Test Technical Asset</b> as an example)", risks[0].Title)
}

func TestMissingBuildInfrastructureRuleGenerateRisksTechnicalAssetCriticalIntegrityRisksCreatedWithMediumImpact(t *testing.T) {
	rule := NewMissingBuildInfrastructureRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				Integrity:            types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>Test Technical Asset</b> as an example)", risks[0].Title)
}

func TestMissingBuildInfrastructureRuleGenerateRisksTechnicalAssetCriticalAvailabilityRisksCreatedWithMediumImpact(t *testing.T) {
	rule := NewMissingBuildInfrastructureRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:                "Test Technical Asset",
				CustomDevelopedParts: true,
				Availability:         types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, "<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>Test Technical Asset</b> as an example)", risks[0].Title)
}
