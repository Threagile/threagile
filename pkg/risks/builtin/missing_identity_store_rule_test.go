package builtin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestMissingIdentityStoreRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewMissingIdentityStoreRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingIdentityStoreRuleGenerateRisksThereIsIdenityStoreWithinScopeNoRisksCreated(t *testing.T) {
	rule := NewMissingIdentityStoreRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "some-technology",
						Attributes: map[string]bool{
							types.IsIdentityStore: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestMissingIdentityStoreRuleGenerateRisksNoEndUserIdentityPropagationNoRisksCreated(t *testing.T) {
	rule := NewMissingIdentityStoreRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
			},
			"ta2": {
				Title:      "Test Sparring Technical Asset",
				OutOfScope: false,
				CommunicationLinks: []*types.CommunicationLink{
					{
						TargetId:      "ta1",
						Authorization: types.NoneAuthorization,
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type MissingIdentityStoreRuleTest struct {
	targetConfidentiality types.Confidentiality
	targetIntegrity       types.Criticality
	targetAvailability    types.Criticality

	dataProcessedConfidentiality types.Confidentiality
	dataProcessedIntegrity       types.Criticality
	dataProcessedAvailability    types.Criticality

	sourceConfidentiality types.Confidentiality
	sourceIntegrity       types.Criticality
	sourceAvailability    types.Criticality

	expectedImpact                 types.RiskExploitationImpact
	expectedMostRelevantAssetTitle string
}

func TestMissingIdentityStoreRule(t *testing.T) {
	testCases := map[string]MissingIdentityStoreRuleTest{
		"low impact": {
			targetConfidentiality: types.Restricted,
			targetAvailability:    types.Important,
			targetIntegrity:       types.Important,

			dataProcessedConfidentiality: types.Restricted,
			dataProcessedIntegrity:       types.Important,
			dataProcessedAvailability:    types.Important,

			sourceConfidentiality: types.Restricted,
			sourceIntegrity:       types.Important,
			sourceAvailability:    types.Important,

			expectedImpact:                 types.LowImpact,
			expectedMostRelevantAssetTitle: "Test Technical Asset",
		},
		"source asset more relevant": {
			targetConfidentiality: types.Restricted,
			targetAvailability:    types.Important,
			targetIntegrity:       types.Important,

			dataProcessedConfidentiality: types.Restricted,
			dataProcessedIntegrity:       types.Important,
			dataProcessedAvailability:    types.Important,

			sourceConfidentiality: types.Confidential,
			sourceIntegrity:       types.Important,
			sourceAvailability:    types.Important,

			expectedImpact:                 types.LowImpact,
			expectedMostRelevantAssetTitle: "Test Sparring Technical Asset",
		},
		"medium impact confidential target asset": {
			targetConfidentiality: types.Confidential,
			targetAvailability:    types.Important,
			targetIntegrity:       types.Important,

			dataProcessedConfidentiality: types.Restricted,
			dataProcessedIntegrity:       types.Important,
			dataProcessedAvailability:    types.Important,

			sourceConfidentiality: types.Restricted,
			sourceIntegrity:       types.Important,
			sourceAvailability:    types.Important,

			expectedImpact:                 types.MediumImpact,
			expectedMostRelevantAssetTitle: "Test Technical Asset",
		},
		"medium impact critical integrity target asset": {
			targetConfidentiality: types.Restricted,
			targetAvailability:    types.Critical,
			targetIntegrity:       types.Important,

			dataProcessedConfidentiality: types.Restricted,
			dataProcessedIntegrity:       types.Important,
			dataProcessedAvailability:    types.Important,

			sourceConfidentiality: types.Restricted,
			sourceIntegrity:       types.Important,
			sourceAvailability:    types.Important,

			expectedImpact:                 types.MediumImpact,
			expectedMostRelevantAssetTitle: "Test Technical Asset",
		},
		"medium impact critical availability target asset": {
			targetConfidentiality: types.Restricted,
			targetAvailability:    types.Important,
			targetIntegrity:       types.Critical,

			dataProcessedConfidentiality: types.Restricted,
			dataProcessedIntegrity:       types.Important,
			dataProcessedAvailability:    types.Important,

			sourceConfidentiality: types.Restricted,
			sourceIntegrity:       types.Important,
			sourceAvailability:    types.Important,

			expectedImpact:                 types.MediumImpact,
			expectedMostRelevantAssetTitle: "Test Technical Asset",
		},
		"medium impact process confidential data asset": {
			targetConfidentiality: types.Restricted,
			targetAvailability:    types.Important,
			targetIntegrity:       types.Important,

			dataProcessedConfidentiality: types.Confidential,
			dataProcessedIntegrity:       types.Important,
			dataProcessedAvailability:    types.Important,

			sourceConfidentiality: types.Restricted,
			sourceIntegrity:       types.Important,
			sourceAvailability:    types.Important,

			expectedImpact:                 types.MediumImpact,
			expectedMostRelevantAssetTitle: "Test Technical Asset",
		},
		"medium impact process critical integrity data asset": {
			targetConfidentiality: types.Restricted,
			targetAvailability:    types.Important,
			targetIntegrity:       types.Important,

			dataProcessedConfidentiality: types.Restricted,
			dataProcessedIntegrity:       types.Critical,
			dataProcessedAvailability:    types.Important,

			sourceConfidentiality: types.Restricted,
			sourceIntegrity:       types.Important,
			sourceAvailability:    types.Important,

			expectedImpact:                 types.MediumImpact,
			expectedMostRelevantAssetTitle: "Test Technical Asset",
		},
		"medium impact process critical availability data asset": {
			targetConfidentiality: types.Restricted,
			targetAvailability:    types.Important,
			targetIntegrity:       types.Important,

			dataProcessedConfidentiality: types.Restricted,
			dataProcessedIntegrity:       types.Important,
			dataProcessedAvailability:    types.Critical,

			sourceConfidentiality: types.Restricted,
			sourceIntegrity:       types.Important,
			sourceAvailability:    types.Important,

			expectedImpact:                 types.MediumImpact,
			expectedMostRelevantAssetTitle: "Test Technical Asset",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewMissingIdentityStoreRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Title:               "Test Technical Asset",
						OutOfScope:          false,
						Availability:        testCase.targetAvailability,
						Confidentiality:     testCase.targetConfidentiality,
						Integrity:           testCase.targetIntegrity,
						DataAssetsProcessed: []string{"da1"},
					},
					"ta2": {
						Title:           "Test Sparring Technical Asset",
						OutOfScope:      false,
						Availability:    testCase.sourceAvailability,
						Confidentiality: testCase.sourceConfidentiality,
						Integrity:       testCase.sourceIntegrity,
						CommunicationLinks: []*types.CommunicationLink{
							{
								TargetId:      "ta1",
								Authorization: types.EndUserIdentityPropagation,
							},
						},
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"da1": {
						Title:           "Test Data Asset",
						Availability:    testCase.dataProcessedAvailability,
						Confidentiality: testCase.dataProcessedConfidentiality,
						Integrity:       testCase.dataProcessedIntegrity,
					},
				},
			})

			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
			expTitle := fmt.Sprintf("<b>Missing Identity Store</b> in the threat model (referencing asset <b>%s</b> as an example)", testCase.expectedMostRelevantAssetTitle)
			assert.Equal(t, expTitle, risks[0].Title)
		})
	}
}
