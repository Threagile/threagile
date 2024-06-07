package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestUnnecessaryDataTransferRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataTransferRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryDataTransferRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataTransferRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				OutOfScope: true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryDataTransferRuleGenerateRisksIsUnnecessaryDataToleratedNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataTransferRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"source": {
				Id:         "source",
				Title:      "Source Technical Asset",
				OutOfScope: false,
				CommunicationLinks: []*types.CommunicationLink{
					{
						TargetId: "target",
					},
				},
			},
			"target": {
				Id:         "target",
				Title:      "Target Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Attributes: map[string]bool{
							types.IsUnnecessaryDataTolerated: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryDataTransferRuleGenerateRisksIsUnnecessaryDataToleratedForSourceNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataTransferRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"source": {
				Id:         "source",
				Title:      "Source Technical Asset",
				OutOfScope: false,
				CommunicationLinks: []*types.CommunicationLink{
					{
						SourceId: "source",
						TargetId: "target",
					},
				},
				Technologies: types.TechnologyList{
					{
						Attributes: map[string]bool{
							types.IsUnnecessaryDataTolerated: true,
						},
					},
				},
			},
			"target": {
				Id:         "target",
				Title:      "Target Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Attributes: map[string]bool{
							types.IsUnnecessaryDataTolerated: true,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"target": {
				{
					SourceId: "source",
					TargetId: "target",
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryDataTransferRuleGenerateRisksSentDataAssetProcessedNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataTransferRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"source": {
				Id:         "source",
				Title:      "Source Technical Asset",
				OutOfScope: false,
				CommunicationLinks: []*types.CommunicationLink{
					{
						SourceId:       "source",
						TargetId:       "target",
						DataAssetsSent: []string{"data"},
					},
				},
			},
			"target": {
				Id:                  "target",
				Title:               "Target Technical Asset",
				OutOfScope:          false,
				DataAssetsProcessed: []string{"data"},
				Technologies: types.TechnologyList{
					{
						Attributes: map[string]bool{
							types.IsUnnecessaryDataTolerated: true,
						},
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"target": {
				{
					SourceId:       "source",
					TargetId:       "target",
					DataAssetsSent: []string{"data"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"data": {
				Id: "data",
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryDataTransferRuleGenerateRisksSentDataAssetWithLowConfidentialityAndIntegrityNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataTransferRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"source": {
				Id:         "source",
				Title:      "Source Technical Asset",
				OutOfScope: false,
				CommunicationLinks: []*types.CommunicationLink{
					{
						SourceId:       "source",
						TargetId:       "target",
						DataAssetsSent: []string{"data"},
					},
				},
			},
			"target": {
				Id:                  "target",
				Title:               "Target Technical Asset",
				OutOfScope:          false,
				DataAssetsProcessed: []string{"data"},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"target": {
				{
					SourceId:       "source",
					TargetId:       "target",
					DataAssetsSent: []string{"data"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"data": {
				Id:              "data",
				Confidentiality: types.Restricted,
				Integrity:       types.Important,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestUnnecessaryDataTransferRuleGenerateRisksReceivedDataAssetProcessedNotRisksCreated(t *testing.T) {
	rule := NewUnnecessaryDataTransferRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"source": {
				Id:                  "source",
				Title:               "Source Technical Asset",
				OutOfScope:          false,
				DataAssetsProcessed: []string{"data"},
				CommunicationLinks: []*types.CommunicationLink{
					{
						SourceId:           "source",
						TargetId:           "target",
						DataAssetsReceived: []string{"data"},
					},
				},
			},
			"target": {
				Id:         "target",
				Title:      "Target Technical Asset",
				OutOfScope: false,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"target": {
				{
					SourceId:           "source",
					TargetId:           "target",
					DataAssetsReceived: []string{"data"},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"data": {
				Id: "data",
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type UnnecessaryDataTransferRuleTest struct {
	dataAssetConfidentiality types.Confidentiality
	dataAssetIntegrity       types.Criticality

	expectedImpact types.RiskExploitationImpact
}

func TestUnnecessaryDataTransferRuleSendDataAssetRisksCreated(t *testing.T) {
	testCases := map[string]UnnecessaryDataTransferRuleTest{
		"low impact": {
			dataAssetConfidentiality: types.Confidential,
			dataAssetIntegrity:       types.Critical,
			expectedImpact:           types.LowImpact,
		},
		"strictly confidential medium impact": {
			dataAssetConfidentiality: types.StrictlyConfidential,
			dataAssetIntegrity:       types.Critical,
			expectedImpact:           types.MediumImpact,
		},
		"mission critical integriyt medium impact": {
			dataAssetConfidentiality: types.Confidential,
			dataAssetIntegrity:       types.MissionCritical,
			expectedImpact:           types.MediumImpact,
		},
	}
	for name, testCases := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewUnnecessaryDataTransferRule()

			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"source": {
						Id:         "source",
						Title:      "Source Technical Asset",
						OutOfScope: false,
						CommunicationLinks: []*types.CommunicationLink{
							{
								Title:          "Data Transfer",
								SourceId:       "source",
								TargetId:       "target",
								DataAssetsSent: []string{"data"},
							},
						},
					},
					"target": {
						Id:                  "target",
						Title:               "Target Technical Asset",
						OutOfScope:          false,
						DataAssetsProcessed: []string{"data"},
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"target": {
						{
							Title:          "Data Transfer",
							SourceId:       "source",
							TargetId:       "target",
							DataAssetsSent: []string{"data"},
						},
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"data": {
						Id:              "data",
						Confidentiality: testCases.dataAssetConfidentiality,
						Integrity:       testCases.dataAssetIntegrity,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCases.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, "<b>Unnecessary Data Transfer</b> of <b></b> data at <b>Source Technical Asset</b> from/to <b>Target Technical Asset</b>", risks[0].Title)
		})
	}
}

func TestUnnecessaryDataTransferRuleReceivedDataAssetRisksCreated(t *testing.T) {
	testCases := map[string]UnnecessaryDataTransferRuleTest{
		"low impact": {
			dataAssetConfidentiality: types.Confidential,
			dataAssetIntegrity:       types.Critical,
			expectedImpact:           types.LowImpact,
		},
		"strictly confidential medium impact": {
			dataAssetConfidentiality: types.StrictlyConfidential,
			dataAssetIntegrity:       types.Critical,
			expectedImpact:           types.MediumImpact,
		},
		"mission critical integriyt medium impact": {
			dataAssetConfidentiality: types.Confidential,
			dataAssetIntegrity:       types.MissionCritical,
			expectedImpact:           types.MediumImpact,
		},
	}
	for name, testCases := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewUnnecessaryDataTransferRule()

			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"source": {
						Id:         "source",
						Title:      "Source Technical Asset",
						OutOfScope: false,
						CommunicationLinks: []*types.CommunicationLink{
							{
								Title:              "Data Transfer",
								SourceId:           "source",
								TargetId:           "target",
								DataAssetsReceived: []string{"data"},
							},
						},
					},
					"target": {
						Id:                  "target",
						Title:               "Target Technical Asset",
						OutOfScope:          false,
						DataAssetsProcessed: []string{"data"},
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"target": {
						{
							Title:              "Data Transfer",
							SourceId:           "source",
							TargetId:           "target",
							DataAssetsReceived: []string{"data"},
						},
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"data": {
						Id:              "data",
						Confidentiality: testCases.dataAssetConfidentiality,
						Integrity:       testCases.dataAssetIntegrity,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCases.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, "<b>Unnecessary Data Transfer</b> of <b></b> data at <b>Source Technical Asset</b> from/to <b>Target Technical Asset</b>", risks[0].Title)
		})
	}
}

func TestUnnecessaryDataTransferRuleSendDataAssetInverseDirectionRisksCreated(t *testing.T) {
	testCases := map[string]UnnecessaryDataTransferRuleTest{
		"low impact": {
			dataAssetConfidentiality: types.Confidential,
			dataAssetIntegrity:       types.Critical,
			expectedImpact:           types.LowImpact,
		},
		"strictly confidential medium impact": {
			dataAssetConfidentiality: types.StrictlyConfidential,
			dataAssetIntegrity:       types.Critical,
			expectedImpact:           types.MediumImpact,
		},
		"mission critical integriyt medium impact": {
			dataAssetConfidentiality: types.Confidential,
			dataAssetIntegrity:       types.MissionCritical,
			expectedImpact:           types.MediumImpact,
		},
	}
	for name, testCases := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewUnnecessaryDataTransferRule()

			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"source": {
						Id:         "source",
						Title:      "Source Technical Asset",
						OutOfScope: false,
					},
					"target": {
						Id:                  "target",
						Title:               "Target Technical Asset",
						OutOfScope:          false,
						DataAssetsProcessed: []string{"data"},
						CommunicationLinks: []*types.CommunicationLink{
							{
								Title:          "Data Transfer",
								SourceId:       "target",
								TargetId:       "source",
								DataAssetsSent: []string{"data"},
							},
						},
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"source": {
						{
							Title:          "Data Transfer",
							SourceId:       "target",
							TargetId:       "source",
							DataAssetsSent: []string{"data"},
						},
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"data": {
						Id:              "data",
						Confidentiality: testCases.dataAssetConfidentiality,
						Integrity:       testCases.dataAssetIntegrity,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCases.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, "<b>Unnecessary Data Transfer</b> of <b></b> data at <b>Source Technical Asset</b> from/to <b>Target Technical Asset</b>", risks[0].Title)
		})
	}
}

func TestUnnecessaryDataTransferRuleReceivedDataAssetInverseDirectionRisksCreated(t *testing.T) {
	testCases := map[string]UnnecessaryDataTransferRuleTest{
		"low impact": {
			dataAssetConfidentiality: types.Confidential,
			dataAssetIntegrity:       types.Critical,
			expectedImpact:           types.LowImpact,
		},
		"strictly confidential medium impact": {
			dataAssetConfidentiality: types.StrictlyConfidential,
			dataAssetIntegrity:       types.Critical,
			expectedImpact:           types.MediumImpact,
		},
		"mission critical integriyt medium impact": {
			dataAssetConfidentiality: types.Confidential,
			dataAssetIntegrity:       types.MissionCritical,
			expectedImpact:           types.MediumImpact,
		},
	}
	for name, testCases := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewUnnecessaryDataTransferRule()

			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"source": {
						Id:         "source",
						Title:      "Source Technical Asset",
						OutOfScope: false,
					},
					"target": {
						Id:                  "target",
						Title:               "Target Technical Asset",
						OutOfScope:          false,
						DataAssetsProcessed: []string{"data"},
						CommunicationLinks: []*types.CommunicationLink{
							{
								Title:              "Data Transfer",
								SourceId:           "target",
								TargetId:           "source",
								DataAssetsReceived: []string{"data"},
							},
						},
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"source": {
						{
							Title:              "Data Transfer",
							SourceId:           "target",
							TargetId:           "source",
							DataAssetsReceived: []string{"data"},
						},
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"data": {
						Id:              "data",
						Confidentiality: testCases.dataAssetConfidentiality,
						Integrity:       testCases.dataAssetIntegrity,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCases.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, "<b>Unnecessary Data Transfer</b> of <b></b> data at <b>Source Technical Asset</b> from/to <b>Target Technical Asset</b>", risks[0].Title)
		})
	}
}

func TestUnnecessaryDataTransferRuleGenerateRisksNoDuplicatedRisksCreated(t *testing.T) {
	testCases := map[string]UnnecessaryDataTransferRuleTest{
		"low impact": {
			dataAssetConfidentiality: types.Confidential,
			dataAssetIntegrity:       types.Critical,
			expectedImpact:           types.LowImpact,
		},
		"strictly confidential medium impact": {
			dataAssetConfidentiality: types.StrictlyConfidential,
			dataAssetIntegrity:       types.Critical,
			expectedImpact:           types.MediumImpact,
		},
		"mission critical integriyt medium impact": {
			dataAssetConfidentiality: types.Confidential,
			dataAssetIntegrity:       types.MissionCritical,
			expectedImpact:           types.MediumImpact,
		},
	}
	for name, testCases := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewUnnecessaryDataTransferRule()

			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"source": {
						Id:         "source",
						Title:      "Source Technical Asset",
						OutOfScope: false,
					},
					"target": {
						Id:                  "target",
						Title:               "Target Technical Asset",
						OutOfScope:          false,
						DataAssetsProcessed: []string{"data"},
						CommunicationLinks: []*types.CommunicationLink{
							{
								Title:              "Data Transfer",
								SourceId:           "target",
								TargetId:           "source",
								DataAssetsReceived: []string{"data"},
							},
							{
								Title:              "Duplication Data Transfer",
								SourceId:           "target",
								TargetId:           "source",
								DataAssetsReceived: []string{"data"},
							},
						},
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"source": {
						{
							Title:              "Data Transfer",
							SourceId:           "target",
							TargetId:           "source",
							DataAssetsReceived: []string{"data"},
						},
						{
							Title:              "Duplication Data Transfer",
							SourceId:           "target",
							TargetId:           "source",
							DataAssetsReceived: []string{"data"},
						},
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"data": {
						Id:              "data",
						Confidentiality: testCases.dataAssetConfidentiality,
						Integrity:       testCases.dataAssetIntegrity,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCases.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, "<b>Unnecessary Data Transfer</b> of <b></b> data at <b>Source Technical Asset</b> from/to <b>Target Technical Asset</b>", risks[0].Title)
		})
	}
}
