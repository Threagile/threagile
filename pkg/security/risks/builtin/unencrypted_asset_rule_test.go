package builtin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestUnencryptedAssetRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewUnencryptedAssetRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type UnencryptedAssetRuleTest struct {
	isEmbeddedComponent         bool
	isNoStorageAtRest           bool
	isUsuallyStoringEndUserData bool
	storedAnyData               bool
	outOfScope                  bool
	encryption                  types.EncryptionStyle
	dataConfidentiality         types.Confidentiality
	dataIntegrity               types.Criticality

	riskCreated         bool
	expectedImpact      types.RiskExploitationImpact
	expectedSuffixTitle string
}

func TestUnencryptedAssetRuleGenerateRisks(t *testing.T) {
	testCases := map[string]UnencryptedAssetRuleTest{
		"out of scope": {
			outOfScope:          true,
			isNoStorageAtRest:   false,
			isEmbeddedComponent: false,
			storedAnyData:       true,
			dataConfidentiality: types.StrictlyConfidential,
			dataIntegrity:       types.MissionCritical,

			riskCreated: false,
		},
		"encryption waiver because no storage at rest": {
			outOfScope:          false,
			isNoStorageAtRest:   true,
			isEmbeddedComponent: false,
			storedAnyData:       true,
			dataConfidentiality: types.StrictlyConfidential,
			dataIntegrity:       types.MissionCritical,

			riskCreated: false,
		},
		"encryption waiver because embedded component": {
			outOfScope:          false,
			isNoStorageAtRest:   false,
			isEmbeddedComponent: true,
			storedAnyData:       true,
			dataConfidentiality: types.StrictlyConfidential,
			dataIntegrity:       types.MissionCritical,

			riskCreated: false,
		},
		"do not store any data": {
			outOfScope:          false,
			isNoStorageAtRest:   false,
			isEmbeddedComponent: false,
			storedAnyData:       false,
			dataConfidentiality: types.StrictlyConfidential,
			dataIntegrity:       types.MissionCritical,

			riskCreated: false,
		},
		"confidentiality restricted and integrity operational": {
			outOfScope:          false,
			isNoStorageAtRest:   false,
			isEmbeddedComponent: false,
			storedAnyData:       true,
			dataConfidentiality: types.Restricted,
			dataIntegrity:       types.Operational,

			riskCreated: false,
		},
		"encrypted not very sensitive": {
			outOfScope:          false,
			isNoStorageAtRest:   false,
			isEmbeddedComponent: false,
			storedAnyData:       true,
			dataConfidentiality: types.Confidential,
			dataIntegrity:       types.Critical,
			encryption:          types.Transparent,

			riskCreated: false,
		},
		"very sensitive end user individual Key": {
			outOfScope:          false,
			isNoStorageAtRest:   false,
			isEmbeddedComponent: false,
			storedAnyData:       true,
			dataConfidentiality: types.StrictlyConfidential,
			dataIntegrity:       types.MissionCritical,
			encryption:          types.DataWithEndUserIndividualKey,

			riskCreated: false,
		},
		"not very sensitive no encryption": {
			outOfScope:          false,
			isNoStorageAtRest:   false,
			isEmbeddedComponent: false,
			storedAnyData:       true,
			dataConfidentiality: types.Confidential,
			dataIntegrity:       types.Critical,
			encryption:          types.NoneEncryption,

			riskCreated:    true,
			expectedImpact: types.MediumImpact,
		},
		"very sensitive strictly confidential no encryption": {
			outOfScope:          false,
			isNoStorageAtRest:   false,
			isEmbeddedComponent: false,
			storedAnyData:       true,
			dataConfidentiality: types.StrictlyConfidential,
			dataIntegrity:       types.Critical,
			encryption:          types.NoneEncryption,

			riskCreated:    true,
			expectedImpact: types.HighImpact,
		},
		"very sensitive mission critical no encryption": {
			outOfScope:          false,
			isNoStorageAtRest:   false,
			isEmbeddedComponent: false,
			storedAnyData:       true,
			dataConfidentiality: types.Confidential,
			dataIntegrity:       types.MissionCritical,
			encryption:          types.NoneEncryption,

			riskCreated:    true,
			expectedImpact: types.HighImpact,
		},
		"very sensitive transparent encryption": {
			outOfScope:                  false,
			isNoStorageAtRest:           false,
			isEmbeddedComponent:         false,
			isUsuallyStoringEndUserData: true,
			storedAnyData:               true,
			dataConfidentiality:         types.StrictlyConfidential,
			dataIntegrity:               types.MissionCritical,
			encryption:                  types.Transparent,

			riskCreated:         true,
			expectedImpact:      types.MediumImpact,
			expectedSuffixTitle: " missing end user individual encryption with data-with-end-user-individual-key",
		},
		"very sensitive DataWithSymmetricSharedKey encryption": {
			outOfScope:                  false,
			isNoStorageAtRest:           false,
			isEmbeddedComponent:         false,
			isUsuallyStoringEndUserData: true,
			storedAnyData:               true,
			dataConfidentiality:         types.StrictlyConfidential,
			dataIntegrity:               types.MissionCritical,
			encryption:                  types.DataWithSymmetricSharedKey,

			riskCreated:         true,
			expectedImpact:      types.MediumImpact,
			expectedSuffixTitle: " missing end user individual encryption with data-with-end-user-individual-key",
		},
		"very sensitive DataWithAsymmetricSharedKey encryption": {
			outOfScope:                  false,
			isNoStorageAtRest:           false,
			isEmbeddedComponent:         false,
			isUsuallyStoringEndUserData: true,
			storedAnyData:               true,
			dataConfidentiality:         types.StrictlyConfidential,
			dataIntegrity:               types.MissionCritical,
			encryption:                  types.DataWithAsymmetricSharedKey,

			riskCreated:         true,
			expectedImpact:      types.MediumImpact,
			expectedSuffixTitle: " missing end user individual encryption with data-with-end-user-individual-key",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewUnencryptedAssetRule()
			dataAssetsStore := []string{}
			if testCase.storedAnyData {
				dataAssetsStore = append(dataAssetsStore, "da1")
			}
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Title:      "Test Technical Asset",
						OutOfScope: testCase.outOfScope,
						Technologies: types.TechnologyList{
							{
								Name: "service-registry",
								Attributes: map[string]bool{
									types.IsEmbeddedComponent:         testCase.isEmbeddedComponent,
									types.IsNoStorageAtRest:           testCase.isNoStorageAtRest,
									types.IsUsuallyStoringEndUserData: testCase.isUsuallyStoringEndUserData,
								},
							},
						},
						DataAssetsStored: dataAssetsStore,
						Encryption:       testCase.encryption,
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"da1": {
						Title:           "Test Data Asset",
						Confidentiality: testCase.dataConfidentiality,
						Integrity:       testCase.dataIntegrity,
					},
				},
			})

			assert.Nil(t, err)
			if testCase.riskCreated {
				assert.NotEmpty(t, risks)
				assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
				expectedMessage := fmt.Sprintf("<b>Unencrypted Technical Asset</b> named <b>Test Technical Asset</b>%s", testCase.expectedSuffixTitle)
				assert.Equal(t, risks[0].Title, expectedMessage)
			} else {
				assert.Empty(t, risks)
			}
		})
	}
}
