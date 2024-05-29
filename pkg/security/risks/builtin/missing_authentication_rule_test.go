package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestMissingAuthenticationRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationRule()

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

func TestMissingAuthenticationRuleGenerateRisksTechnicalAssetWithoutCommunicationLinksNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "Test Technical Asset",
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationRuleGenerateRisksTechnicalAssetWithoutAuthenticationRequiredNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "Test Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.NoAuthenticationRequired: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationRuleGenerateRisksTechnicalAssetMultiTenantWithoutCommunicationLinksNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:       "Test Technical Asset",
				MultiTenant: true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationRuleGenerateRisksCallerFromDatastoreNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"ta2": {
				Id:    "ta2",
				Title: "Test Datastore",
				Type:  types.Datastore,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId: "ta2",
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationRuleGenerateRisksCallerTechnologyTolerateUnprotectedCommunicationsNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"ta2": {
				Id:    "ta2",
				Title: "Test Monitoring",
				Technologies: types.TechnologyList{
					{
						Name: "monitoring",
						Attributes: map[string]bool{
							types.IsUnprotectedCommunicationsTolerated: true,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId: "ta2",
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationRuleGenerateRisksAuthenticationPresentedNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"ta2": {
				Id:    "ta2",
				Title: "User Interface",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId:       "ta2",
					Authentication: types.ClientCertificate,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationRuleGenerateRisksLocalProcessRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"ta2": {
				Id:    "ta2",
				Title: "File scrapper",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId:       "ta2",
					Authentication: types.NoneAuthentication,
					Protocol:       types.LocalFileAccess,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationRuleGenerateRisksNoneAuthenticationMultiTenantNonLocalProcessRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"ta2": {
				Id:    "ta2",
				Title: "User Interface",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					Title:          "User Access via Browser",
					SourceId:       "ta2",
					Authentication: types.NoneAuthentication,
					Protocol:       types.HTTPS,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Missing Authentication</b> covering communication link <b>User Access via Browser</b> from <b>User Interface</b> to <b>Test Technical Asset</b>", risks[0].Title)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestMissingAuthenticationRuleGenerateRisksSendStrictlyConfidentialDataAssetRisksCreatedWithHighImpact(t *testing.T) {
	rule := NewMissingAuthenticationRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"ta2": {
				Id:    "ta2",
				Title: "User Interface",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					Title:          "User Access via Browser",
					SourceId:       "ta2",
					Authentication: types.NoneAuthentication,
					Protocol:       types.HTTPS,
					DataAssetsSent: []string{"strictly-confidential"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"strictly-confidential": {
				Id:              "strictly-confidential",
				Title:           "Strictly Confidential Data",
				Confidentiality: types.StrictlyConfidential,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Missing Authentication</b> covering communication link <b>User Access via Browser</b> from <b>User Interface</b> to <b>Test Technical Asset</b>", risks[0].Title)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}

func TestMissingAuthenticationRuleGenerateRisksOperationalIntegrityRisksCreatedWithLowImpact(t *testing.T) {
	rule := NewMissingAuthenticationRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"ta2": {
				Id:    "ta2",
				Title: "User Interface",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					Title:          "User Access via Browser",
					SourceId:       "ta2",
					Authentication: types.NoneAuthentication,
					Protocol:       types.HTTPS,
					DataAssetsSent: []string{"operational"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"operational": {
				Id:        "operational",
				Title:     "Operational Data",
				Integrity: types.Operational,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Missing Authentication</b> covering communication link <b>User Access via Browser</b> from <b>User Interface</b> to <b>Test Technical Asset</b>", risks[0].Title)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}
