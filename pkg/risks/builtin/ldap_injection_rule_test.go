package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestLdapInjectionRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewLdapInjectionRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestLdapInjectionRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewLdapInjectionRule()

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

func TestLdapInjectionRuleGenerateRisksNoIncomingFlowsNotRisksCreated(t *testing.T) {
	rule := NewLdapInjectionRule()

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

func TestLdapInjectionRuleIncomingFlowFromOutOfScopeAssetNotRisksCreated(t *testing.T) {
	rule := NewLdapInjectionRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Test Technical Asset",
			},
			"ta2": {
				Id:         "ta2",
				Title:      "LDAP Server",
				OutOfScope: true,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId: "ta2",
					Protocol: types.LDAP,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestLdapInjectionRuleIncomingLdapFlowRisksCreated(t *testing.T) {
	rule := NewLdapInjectionRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Test Technical Asset",
			},
			"ta2": {
				Id:    "ta2",
				Title: "LDAP Server",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					Title:    "LDAP Communication",
					SourceId: "ta2",
					Protocol: types.LDAP,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>LDAP-Injection</b> risk at <b>LDAP Server</b> against LDAP server <b>Test Technical Asset</b> via <b>LDAP Communication</b>", risks[0].Title)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestLdapInjectionRuleIncomingLdapFlowDevOpsUsageRisksCreated_WithUnlikelyLikelihood(t *testing.T) {
	rule := NewLdapInjectionRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Test Technical Asset",
			},
			"ta2": {
				Id:    "ta2",
				Title: "LDAP Server",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					Title:    "LDAP Communication",
					SourceId: "ta2",
					Protocol: types.LDAP,
					Usage:    types.DevOps,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>LDAP-Injection</b> risk at <b>LDAP Server</b> against LDAP server <b>Test Technical Asset</b> via <b>LDAP Communication</b>", risks[0].Title)
	assert.Equal(t, types.Unlikely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestLdapInjectionRuleIncomingLdapFlowProcessStrictlyConfidentialDataAssetsRisksCreated(t *testing.T) {
	rule := NewLdapInjectionRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:                  "ta1",
				Title:               "Test Technical Asset",
				DataAssetsProcessed: []string{"da1"},
			},
			"ta2": {
				Id:    "ta2",
				Title: "LDAP Server",
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					Title:    "LDAP Communication",
					SourceId: "ta2",
					Protocol: types.LDAP,
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Id:              "da1",
				Title:           "Strictly Confidential Data Asset",
				Confidentiality: types.StrictlyConfidential,
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>LDAP-Injection</b> risk at <b>LDAP Server</b> against LDAP server <b>Test Technical Asset</b> via <b>LDAP Communication</b>", risks[0].Title)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}
