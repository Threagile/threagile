package builtin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestXmlExternalEntityRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewXmlExternalEntityRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type XmlExternalEntityRuleTest struct {
	outOfScope      bool
	acceptedFormat  types.DataFormat
	confidentiality types.Confidentiality
	integrity       types.Criticality
	availability    types.Criticality

	riskCreated bool
	expImpact   types.RiskExploitationImpact
}

func TestXmlExternalEntityRuleSendDataAssetRisksCreated(t *testing.T) {
	testCases := map[string]XmlExternalEntityRuleTest{
		"out of scope": {
			outOfScope:  true,
			riskCreated: false,
		},
		"json": {
			acceptedFormat: types.JSON,
			riskCreated:    false,
		},
		"serialization": {
			acceptedFormat: types.Serialization,
			riskCreated:    false,
		},
		"file": {
			acceptedFormat: types.File,
			riskCreated:    false,
		},
		"csv": {
			acceptedFormat: types.CSV,
			riskCreated:    false,
		},
		"yaml": {
			acceptedFormat: types.YAML,
			riskCreated:    false,
		},
		"xml": {
			acceptedFormat:  types.XML,
			confidentiality: types.Confidential,
			integrity:       types.Critical,
			availability:    types.Critical,
			riskCreated:     true,
			expImpact:       types.MediumImpact,
		},
		"strictly confidential": {
			acceptedFormat:  types.XML,
			confidentiality: types.StrictlyConfidential,
			integrity:       types.Critical,
			availability:    types.Critical,
			riskCreated:     true,
			expImpact:       types.HighImpact,
		},
		"mission critical integrity": {
			acceptedFormat:  types.XML,
			confidentiality: types.Confidential,
			integrity:       types.MissionCritical,
			availability:    types.Critical,
			riskCreated:     true,
			expImpact:       types.HighImpact,
		},
		"mission critical availability": {
			acceptedFormat:  types.XML,
			confidentiality: types.Confidential,
			integrity:       types.Critical,
			availability:    types.MissionCritical,
			riskCreated:     true,
			expImpact:       types.HighImpact,
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewXmlExternalEntityRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta": {
						Id:         "ta",
						Title:      "Test Technical Asset",
						OutOfScope: testCase.outOfScope,
						DataFormatsAccepted: []types.DataFormat{
							testCase.acceptedFormat,
						},
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
						Availability:    testCase.availability,
					},
				},
			})

			assert.Nil(t, err)
			if testCase.riskCreated {
				assert.Len(t, risks, 1)
				assert.Equal(t, testCase.expImpact, risks[0].ExploitationImpact)
				expTitle := fmt.Sprintf("<b>XML External Entity (XXE)</b> risk at <b>%s</b>", "Test Technical Asset")
				assert.Equal(t, expTitle, risks[0].Title)
			} else {
				assert.Empty(t, risks)
			}
		})
	}
}
