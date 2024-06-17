package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestMissingAuthenticationSecondFactorRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationSecondFactorRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

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

func TestMissingAuthenticationSecondFactorRuleGenerateRisksTrafficForwardingTechnologyNotRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "Test Technical Asset",
				Technologies: types.TechnologyList{
					{
						Name: "load-balancer",
						Attributes: map[string]bool{
							types.IsTrafficForwarding: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationSecondFactorRuleGenerateRisksUnprotectedCommunicationToleratedNotRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title: "Test Technical Asset",
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
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationSecondFactorRuleGenerateRisksCallerFromDatastoreNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

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

func TestMissingAuthenticationSecondFactorRuleGenerateRisksCallerUnprotectedCommunicationToleratedNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

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

func TestMissingAuthenticationSecondFactorRuleUsedAsClientByHumanLessRiskyDataSentTwoFactorAuthenticationEnabledNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"ta2": {
				Id:                  "ta2",
				Title:               "Browser",
				UsedAsClientByHuman: true,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId:       "ta2",
					Authentication: types.TwoFactor,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationSecondFactorRuleUsedAsClientByHumanCriticalIntegrityDataAccessRiskyDataSentTwoFactorAuthenticationEnabledNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"ta2": {
				Id:                  "ta2",
				Title:               "Browser",
				UsedAsClientByHuman: true,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId:       "ta2",
					Authentication: types.TwoFactor,
					DataAssetsSent: []string{"da1"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Id:        "da1",
				Title:     "Test Data Asset",
				Integrity: types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationSecondFactorRuleUsedAsClientByHumanConfidentialDataSentTwoFactorAuthenticationDisabledRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"ta2": {
				Id:                  "ta2",
				Title:               "Browser",
				UsedAsClientByHuman: true,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId:       "ta2",
					Title:          "Access confidential data with client certificate",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Id:              "da1",
				Title:           "Test Data Asset",
				Confidentiality: types.Confidential,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Missing Two-Factor Authentication</b> covering communication link <b>Access confidential data with client certificate</b> from <b>Browser</b> to <b>Test Technical Asset</b>", risks[0].Title)
}

func TestMissingAuthenticationSecondFactorRuleNotUsedAsClientByHumanAndNotTrafficForwardingCriticalIntegrityDataAccessRiskyDataSentTwoFactorAuthenticationEnabledNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"ta2": {
				Id:    "ta2",
				Title: "elb",
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.IsTrafficForwarding: false,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId:       "ta2",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Id:        "da1",
				Title:     "Test Data Asset",
				Integrity: types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationSecondFactorRuleNotTrafficForwardingCriticalIntegrityDataAccessRiskyDataSentTwoFactorAuthenticationEnabledNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"ta2": {
				Id:    "ta2",
				Title: "elb",
				Technologies: types.TechnologyList{
					{
						Name: "load-balancer",
						Attributes: map[string]bool{
							types.IsTrafficForwarding: true,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId:       "ta2",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Id:        "da1",
				Title:     "Test Data Asset",
				Integrity: types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationSecondFactorRuleCallersCallerDataStoreNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"elb": {
				Id:    "elb",
				Title: "Load Balancer",
				Technologies: types.TechnologyList{
					{
						Name: "load-balancer",
						Attributes: map[string]bool{
							types.IsTrafficForwarding: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Datastore",
				Type:  types.Datastore,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId:       "elb",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
				},
			},
			"elb": {
				{
					SourceId:       "ta2",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Id:        "da1",
				Title:     "Test Data Asset",
				Integrity: types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationSecondFactorRuleCallersCallerUnprotectedCommunicationsToleratedNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"elb": {
				Id:    "elb",
				Title: "Load Balancer",
				Technologies: types.TechnologyList{
					{
						Name: "load-balancer",
						Attributes: map[string]bool{
							types.IsTrafficForwarding: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Monitoring",
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
					SourceId:       "elb",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
				},
			},
			"elb": {
				{
					SourceId:       "ta2",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Id:        "da1",
				Title:     "Test Data Asset",
				Integrity: types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationSecondFactorRuleCallersCallerNotUsedAsClientByHumanNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"elb": {
				Id:    "elb",
				Title: "Load Balancer",
				Technologies: types.TechnologyList{
					{
						Name: "load-balancer",
						Attributes: map[string]bool{
							types.IsTrafficForwarding: true,
						},
					},
				},
			},
			"ta2": {
				Id:    "ta2",
				Title: "Tool",
				Technologies: types.TechnologyList{
					{
						Name: "tool",
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId:       "elb",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
				},
			},
			"elb": {
				{
					SourceId:       "ta2",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Id:        "da1",
				Title:     "Test Data Asset",
				Integrity: types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationSecondFactorRuleCallersCallerProcessLessRiskyDataNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"elb": {
				Id:    "elb",
				Title: "Load Balancer",
				Technologies: types.TechnologyList{
					{
						Name: "load-balancer",
						Attributes: map[string]bool{
							types.IsTrafficForwarding: true,
						},
					},
				},
			},
			"ta2": {
				Id:                  "ta2",
				Title:               "Browser",
				UsedAsClientByHuman: true,
				Technologies: types.TechnologyList{
					{
						Name: "browser",
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId:       "elb",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
				},
			},
			"elb": {
				{
					SourceId:       "ta2",
					Authentication: types.TwoFactor,
					DataAssetsSent: []string{"da1"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Id:        "da1",
				Title:     "Test Data Asset",
				Integrity: types.Important,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationSecondFactorRuleCallersCallerProcessCriticalDataTwoFactorEnabledNoRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"elb": {
				Id:    "elb",
				Title: "Load Balancer",
				Technologies: types.TechnologyList{
					{
						Name: "load-balancer",
						Attributes: map[string]bool{
							types.IsTrafficForwarding: true,
						},
					},
				},
			},
			"ta2": {
				Id:                  "ta2",
				Title:               "Browser",
				UsedAsClientByHuman: true,
				Technologies: types.TechnologyList{
					{
						Name: "browser",
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId:       "elb",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
				},
			},
			"elb": {
				{
					SourceId:       "ta2",
					Authentication: types.TwoFactor,
					DataAssetsSent: []string{"da1"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Id:        "da1",
				Title:     "Test Data Asset",
				Integrity: types.Critical,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingAuthenticationSecondFactorRuleCallersCallerProcessConfidentialDataTwoFactorDisabledRisksCreated(t *testing.T) {
	rule := NewMissingAuthenticationSecondFactorRule(NewMissingAuthenticationRule())

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:          "ta1",
				Title:       "Test Technical Asset",
				MultiTenant: true, // require less code instead of adding processed data
			},
			"elb": {
				Id:    "elb",
				Title: "Load Balancer",
				Technologies: types.TechnologyList{
					{
						Name: "load-balancer",
						Attributes: map[string]bool{
							types.IsTrafficForwarding: true,
						},
					},
				},
			},
			"ta2": {
				Id:                  "ta2",
				Title:               "Browser",
				UsedAsClientByHuman: true,
				Technologies: types.TechnologyList{
					{
						Name: "browser",
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta1": {
				{
					SourceId:       "elb",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
					Title:          "Access confidential data with client certificate from load balancer",
				},
			},
			"elb": {
				{
					SourceId:       "ta2",
					Authentication: types.ClientCertificate,
					DataAssetsSent: []string{"da1"},
					Title:          "Access confidential data with client certificate via load balancer by human",
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"da1": {
				Id:              "da1",
				Title:           "Test Data Asset",
				Confidentiality: types.Confidential,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, "<b>Missing Two-Factor Authentication</b> covering communication link <b>Access confidential data with client certificate from load balancer</b> from <b>Browser</b> forwarded via <b>Load Balancer</b> to <b>Test Technical Asset</b>", risks[0].Title)
}
