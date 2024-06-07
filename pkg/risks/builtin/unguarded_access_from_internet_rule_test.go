package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestUnguardedAccessFromInternetRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewUnguardedAccessFromInternetRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type UnguardedAccessFromInternetRuleTest struct {
	outOfScope           bool
	protocol             types.Protocol
	customDevelopedParts bool
	isVPN                bool
	raa                  float64

	isSourceMonitoring   bool
	isSourceFromInternet bool

	isHttpInternetAccessOK bool
	isFTPInternetAccessOK  bool
	isLoadBalancer         bool

	confidentiality types.Confidentiality
	integrity       types.Criticality

	riskCreated    bool
	expectedImpact types.RiskExploitationImpact
}

func TestUnguardedAccessFromInternetRuleGenerateRisks(t *testing.T) {
	testCases := map[string]UnguardedAccessFromInternetRuleTest{
		"out of scope": {
			outOfScope:     true,
			isLoadBalancer: false,

			riskCreated: false,
		},
		"no risk when access from load balancer": {
			outOfScope:     false,
			isLoadBalancer: true,

			riskCreated: false,
		},
		"no risk when access from monitoring": {
			outOfScope:         false,
			isLoadBalancer:     false,
			isSourceMonitoring: true,

			riskCreated: false,
		},
		"no risk when access from vpn": {
			outOfScope:     false,
			isLoadBalancer: false,
			isVPN:          true,

			riskCreated: false,
		},
		"https access from not custom developed parts": {
			outOfScope:             false,
			isLoadBalancer:         false,
			customDevelopedParts:   false,
			isHttpInternetAccessOK: true,
			protocol:               types.HTTPS,

			riskCreated: false,
		},
		"http access from not custom developed parts": {
			outOfScope:             false,
			isLoadBalancer:         false,
			customDevelopedParts:   false,
			isHttpInternetAccessOK: true,
			protocol:               types.HTTP,

			riskCreated: false,
		},
		"ftp access from not custom developed parts": {
			outOfScope:            false,
			isLoadBalancer:        false,
			customDevelopedParts:  false,
			isFTPInternetAccessOK: true,
			protocol:              types.FTP,

			riskCreated: false,
		},
		"ftps access from not custom developed parts": {
			outOfScope:            false,
			isLoadBalancer:        false,
			customDevelopedParts:  false,
			isFTPInternetAccessOK: true,
			protocol:              types.FTPS,

			riskCreated: false,
		},
		"sftp access from not custom developed parts": {
			outOfScope:            false,
			isLoadBalancer:        false,
			customDevelopedParts:  false,
			isFTPInternetAccessOK: true,
			protocol:              types.SFTP,

			riskCreated: false,
		},
		"no risk for low confidentiality and integrity": {
			outOfScope:      false,
			isLoadBalancer:  false,
			isVPN:           false,
			confidentiality: types.Restricted,
			integrity:       types.Operational,

			riskCreated: false,
		},
		"no access from internet": {
			outOfScope:           false,
			isLoadBalancer:       false,
			isVPN:                false,
			isSourceFromInternet: false,
			confidentiality:      types.Confidential,
			integrity:            types.Critical,

			riskCreated: false,
		},
		"low impact risk created": {
			outOfScope:           false,
			isLoadBalancer:       false,
			isVPN:                false,
			isSourceFromInternet: true,
			confidentiality:      types.Confidential,
			integrity:            types.Critical,

			riskCreated:    true,
			expectedImpact: types.LowImpact,
		},
		"raa high impact risk created": {
			outOfScope:           false,
			isLoadBalancer:       false,
			isVPN:                false,
			isSourceFromInternet: true,
			raa:                  50,
			confidentiality:      types.Confidential,
			integrity:            types.Critical,

			riskCreated:    true,
			expectedImpact: types.MediumImpact,
		},
		"strictly confidential medium impact risk created": {
			outOfScope:           false,
			isLoadBalancer:       false,
			isVPN:                false,
			isSourceFromInternet: true,
			confidentiality:      types.StrictlyConfidential,
			integrity:            types.Critical,

			riskCreated:    true,
			expectedImpact: types.MediumImpact,
		},
		"mission critical integrity medium impact risk created": {
			outOfScope:           false,
			isLoadBalancer:       false,
			isVPN:                false,
			isSourceFromInternet: true,
			confidentiality:      types.Confidential,
			integrity:            types.MissionCritical,

			riskCreated:    true,
			expectedImpact: types.MediumImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewUnguardedAccessFromInternetRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"source": {
						Id:       "source",
						Title:    "Source Technical Asset",
						Internet: testCase.isSourceFromInternet,
						Technologies: types.TechnologyList{
							{
								Attributes: map[string]bool{
									types.Monitoring: testCase.isSourceMonitoring,
								},
							},
						},
					},
					"target": {
						Id:                   "target",
						Title:                "Target Technical Asset",
						OutOfScope:           testCase.outOfScope,
						RAA:                  testCase.raa,
						CustomDevelopedParts: testCase.customDevelopedParts,
						CommunicationLinks: []*types.CommunicationLink{
							{
								Title:    "Test Communication Link",
								SourceId: "source",
								TargetId: "target",
								Protocol: testCase.protocol,
								VPN:      testCase.isVPN,
							},
						},
						Technologies: types.TechnologyList{
							{
								Attributes: map[string]bool{
									types.LoadBalancer:           testCase.isLoadBalancer,
									types.IsHTTPInternetAccessOK: testCase.isHttpInternetAccessOK,
									types.IsFTPInternetAccessOK:  testCase.isFTPInternetAccessOK,
								},
							},
						},
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"target": {
						{
							Title:    "Test Communication Link",
							SourceId: "source",
							TargetId: "target",
							Protocol: testCase.protocol,
							VPN:      testCase.isVPN,
						},
					},
				},
			})

			assert.Nil(t, err)
			if testCase.riskCreated {
				assert.NotEmpty(t, risks)
				assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
				expectedMessage := "<b>Unguarded Access from Internet</b> of <b>Target Technical Asset</b> by <b>Source Technical Asset</b> via <b>Test Communication Link</b>"
				assert.Equal(t, risks[0].Title, expectedMessage)
			} else {
				assert.Empty(t, risks)
			}
		})
	}
}
