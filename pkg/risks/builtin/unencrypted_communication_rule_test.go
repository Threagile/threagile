package builtin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestUnencryptedCommunicationRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewUnencryptedCommunicationRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type UnencryptedCommunicationRuleTest struct {
	sourceOutOfScope                        bool
	sourceUnprotectedCommunicationTolerated bool
	targetOutOfScope                        bool
	targetUnprotectedCommunicationTolerated bool
	protocol                                types.Protocol
	authentication                          types.Authentication
	vpnDataFlow                             bool

	sendAnyData              bool
	receiveAnyData           bool
	dataAssetConfidentiality types.Confidentiality
	dataAssetIntegrity       types.Criticality

	isAcrossTrustBoundary bool

	riskCreated         bool
	expectedImpact      types.RiskExploitationImpact
	expectedLikelihood  types.RiskExploitationLikelihood
	expectedSuffixTitle string
}

func TestUnencryptedCommunicationRuleGenerateRisks(t *testing.T) {
	testCases := map[string]UnencryptedCommunicationRuleTest{
		"out of scope": {
			sourceOutOfScope: true,
			targetOutOfScope: true,

			riskCreated: false,
		},
		"unprotected communication tolerated for source": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: true,
			targetUnprotectedCommunicationTolerated: false,
			protocol:                                types.HTTP,

			riskCreated: false,
		},
		"unprotected communication tolerated for target": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: true,
			protocol:                                types.HTTP,

			riskCreated: false,
		},
		"no data sent or received": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             false,
			receiveAnyData:                          false,
			protocol:                                types.HTTP,

			riskCreated: false,
		},
		"send not important data": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             true,
			receiveAnyData:                          false,
			dataAssetConfidentiality:                types.Restricted,
			dataAssetIntegrity:                      types.Operational,
			authentication:                          types.NoneAuthentication,
			protocol:                                types.HTTP,

			riskCreated: false,
		},
		"send important data over VPN": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             true,
			receiveAnyData:                          false,
			dataAssetConfidentiality:                types.Confidential,
			dataAssetIntegrity:                      types.Critical,
			vpnDataFlow:                             true,
			authentication:                          types.NoneAuthentication,
			protocol:                                types.HTTP,

			riskCreated: false,
		},
		"send authentication data": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             true,
			receiveAnyData:                          false,
			dataAssetConfidentiality:                types.Confidential,
			dataAssetIntegrity:                      types.Critical,
			vpnDataFlow:                             false,
			authentication:                          types.Credentials,
			protocol:                                types.HTTP,

			riskCreated:         true,
			expectedImpact:      types.HighImpact,
			expectedSuffixTitle: " transferring authentication data (like credentials, token, session-id, etc.)",
		},
		"send authentication data over VPN": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             true,
			receiveAnyData:                          false,
			dataAssetConfidentiality:                types.Confidential,
			dataAssetIntegrity:                      types.Critical,
			vpnDataFlow:                             true,
			authentication:                          types.Credentials,
			protocol:                                types.HTTP,

			riskCreated:         true,
			expectedImpact:      types.HighImpact,
			expectedSuffixTitle: " transferring authentication data (like credentials, token, session-id, etc.) (even VPN-protected connections need to encrypt their data in-transit when confidentiality is rated strictly-confidential or integrity is rated mission-critical)",
		},
		"send high sensitive data": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             true,
			receiveAnyData:                          false,
			dataAssetConfidentiality:                types.StrictlyConfidential,
			dataAssetIntegrity:                      types.Critical,
			vpnDataFlow:                             false,
			authentication:                          types.NoneAuthentication,
			protocol:                                types.HTTP,

			riskCreated:    true,
			expectedImpact: types.HighImpact,
		},
		"send important data without VPN": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             true,
			receiveAnyData:                          false,
			dataAssetConfidentiality:                types.Confidential,
			dataAssetIntegrity:                      types.Critical,
			vpnDataFlow:                             false,
			authentication:                          types.NoneAuthentication,
			protocol:                                types.HTTP,

			riskCreated:    true,
			expectedImpact: types.MediumImpact,
		},
		"send high sensitive data across trust boundary": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             true,
			receiveAnyData:                          false,
			dataAssetConfidentiality:                types.StrictlyConfidential,
			dataAssetIntegrity:                      types.Critical,
			vpnDataFlow:                             false,
			authentication:                          types.NoneAuthentication,
			protocol:                                types.HTTP,
			isAcrossTrustBoundary:                   true,

			riskCreated:        true,
			expectedImpact:     types.HighImpact,
			expectedLikelihood: types.Likely,
		},
		"receive not important data": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             false,
			receiveAnyData:                          true,
			dataAssetConfidentiality:                types.Restricted,
			dataAssetIntegrity:                      types.Operational,
			authentication:                          types.NoneAuthentication,
			protocol:                                types.HTTP,

			riskCreated: false,
		},
		"receive important data over VPN": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             false,
			receiveAnyData:                          true,
			dataAssetConfidentiality:                types.Confidential,
			dataAssetIntegrity:                      types.Critical,
			vpnDataFlow:                             true,
			authentication:                          types.NoneAuthentication,
			protocol:                                types.HTTP,

			riskCreated: false,
		},
		"receive important data without VPN": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             false,
			receiveAnyData:                          true,
			dataAssetConfidentiality:                types.Confidential,
			dataAssetIntegrity:                      types.Critical,
			vpnDataFlow:                             false,
			authentication:                          types.NoneAuthentication,
			protocol:                                types.HTTP,

			riskCreated:    true,
			expectedImpact: types.MediumImpact,
		},
		"receive authentication data": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             false,
			receiveAnyData:                          true,
			dataAssetConfidentiality:                types.Confidential,
			dataAssetIntegrity:                      types.Critical,
			vpnDataFlow:                             false,
			authentication:                          types.Credentials,
			protocol:                                types.HTTP,

			riskCreated:         true,
			expectedImpact:      types.HighImpact,
			expectedSuffixTitle: " transferring authentication data (like credentials, token, session-id, etc.)",
		},
		"receive authentication data over VPN": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             false,
			receiveAnyData:                          true,
			dataAssetConfidentiality:                types.Confidential,
			dataAssetIntegrity:                      types.Critical,
			vpnDataFlow:                             true,
			authentication:                          types.Credentials,
			protocol:                                types.HTTP,

			riskCreated:         true,
			expectedImpact:      types.HighImpact,
			expectedSuffixTitle: " transferring authentication data (like credentials, token, session-id, etc.) (even VPN-protected connections need to encrypt their data in-transit when confidentiality is rated strictly-confidential or integrity is rated mission-critical)",
		},
		"receive high sensitive data": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             false,
			receiveAnyData:                          true,
			dataAssetConfidentiality:                types.StrictlyConfidential,
			dataAssetIntegrity:                      types.Critical,
			vpnDataFlow:                             false,
			authentication:                          types.NoneAuthentication,
			protocol:                                types.HTTP,

			riskCreated:    true,
			expectedImpact: types.HighImpact,
		},
		"receive high sensitive data across trust boundary": {
			sourceOutOfScope:                        false,
			targetOutOfScope:                        false,
			sourceUnprotectedCommunicationTolerated: false,
			targetUnprotectedCommunicationTolerated: false,
			sendAnyData:                             false,
			receiveAnyData:                          true,
			dataAssetConfidentiality:                types.StrictlyConfidential,
			dataAssetIntegrity:                      types.Critical,
			vpnDataFlow:                             false,
			authentication:                          types.NoneAuthentication,
			protocol:                                types.HTTP,
			isAcrossTrustBoundary:                   true,

			riskCreated:        true,
			expectedImpact:     types.HighImpact,
			expectedLikelihood: types.Likely,
		},
		"HTTPS": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.HTTPS,

			riskCreated: false,
		},
		"WSS": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.WSS,

			riskCreated: false,
		},
		"JdbcEncrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.JdbcEncrypted,

			riskCreated: false,
		},
		"OdbcEncrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.OdbcEncrypted,

			riskCreated: false,
		},
		"NosqlAccessProtocolEncrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.NosqlAccessProtocolEncrypted,

			riskCreated: false,
		},
		"SqlAccessProtocolEncrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.SqlAccessProtocolEncrypted,

			riskCreated: false,
		},
		"BinaryEncrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.BinaryEncrypted,

			riskCreated: false,
		},
		"TextEncrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.TextEncrypted,

			riskCreated: false,
		},
		"SSH": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.SSH,

			riskCreated: false,
		},
		"SshTunnel": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.SshTunnel,

			riskCreated: false,
		},
		"FTPS": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.FTPS,

			riskCreated: false,
		},
		"SFTP": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.SFTP,

			riskCreated: false,
		},
		"SCP": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.SCP,

			riskCreated: false,
		},
		"LDAPS": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.LDAPS,

			riskCreated: false,
		},
		"ReverseProxyWebProtocolEncrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.ReverseProxyWebProtocolEncrypted,

			riskCreated: false,
		},
		"IiopEncrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.IiopEncrypted,

			riskCreated: false,
		},
		"JrmpEncrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.JrmpEncrypted,

			riskCreated: false,
		},
		"SmbEncrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.SmbEncrypted,

			riskCreated: false,
		},
		"SmtpEncrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.SmtpEncrypted,

			riskCreated: false,
		},
		"Pop3Encrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.Pop3Encrypted,

			riskCreated: false,
		},
		"ImapEncrypted": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.Pop3Encrypted,

			riskCreated: false,
		},
		"InProcessLibraryCall": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.InProcessLibraryCall,

			riskCreated: false,
		},
		"InterProcessCommunication": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.InterProcessCommunication,

			riskCreated: false,
		},
		"LocalFileAccess": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.LocalFileAccess,

			riskCreated: false,
		},
		"ContainerSpawning": {
			sourceOutOfScope: false,
			targetOutOfScope: false,
			protocol:         types.ContainerSpawning,

			riskCreated: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewUnencryptedCommunicationRule()
			dataAssetsSend := []string{}
			if testCase.sendAnyData {
				dataAssetsSend = append(dataAssetsSend, "da1")
			}
			dataAssetsReceived := []string{}
			if testCase.receiveAnyData {
				dataAssetsReceived = append(dataAssetsReceived, "da1")
			}
			tb1 := &types.TrustBoundary{
				Id:                    "tb1",
				Title:                 "First Trust Boundary",
				TechnicalAssetsInside: []string{"source", "target"},
				Type:                  types.NetworkCloudProvider,
			}
			tb2 := &types.TrustBoundary{
				Id:    "tb2",
				Title: "Second Trust Boundary",
				Type:  types.NetworkCloudProvider,
			}
			if testCase.isAcrossTrustBoundary {
				tb1.TechnicalAssetsInside = []string{"source"}
				tb2.TechnicalAssetsInside = []string{"target"}
			}

			directContainingTrustBoundaryMappedByTechnicalAssetId := map[string]*types.TrustBoundary{
				"source": tb1,
				"target": tb1,
			}
			if testCase.isAcrossTrustBoundary {
				directContainingTrustBoundaryMappedByTechnicalAssetId["target"] = tb2
			}

			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"source": {
						Id:         "source",
						Title:      "Source Technical Asset",
						OutOfScope: testCase.sourceOutOfScope,
						CommunicationLinks: []*types.CommunicationLink{
							{
								Title:              "Test Communication Link",
								SourceId:           "source",
								TargetId:           "target",
								Authentication:     testCase.authentication,
								Protocol:           testCase.protocol,
								DataAssetsSent:     dataAssetsSend,
								DataAssetsReceived: dataAssetsReceived,
								VPN:                testCase.vpnDataFlow,
							},
						},
						Technologies: types.TechnologyList{
							{
								Name: "service-registry",
								Attributes: map[string]bool{
									types.IsUnprotectedCommunicationsTolerated: testCase.sourceUnprotectedCommunicationTolerated,
								},
							},
						},
					},
					"target": {
						Id:         "target",
						Title:      "Target Technical Asset",
						OutOfScope: testCase.targetOutOfScope,
						Technologies: types.TechnologyList{
							{
								Name: "service-registry",
								Attributes: map[string]bool{
									types.IsUnprotectedCommunicationsTolerated: testCase.targetUnprotectedCommunicationTolerated,
								},
							},
						},
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"da1": {
						Title:           "Test Data Asset",
						Confidentiality: testCase.dataAssetConfidentiality,
						Integrity:       testCase.dataAssetIntegrity,
					},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{
					"tb1": tb1,
					"tb2": tb2,
				},
				DirectContainingTrustBoundaryMappedByTechnicalAssetId: directContainingTrustBoundaryMappedByTechnicalAssetId,
			})

			assert.Nil(t, err)
			if testCase.riskCreated {
				assert.NotEmpty(t, risks)
				assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
				assert.Equal(t, testCase.expectedLikelihood, risks[0].ExploitationLikelihood)
				expectedMessage := fmt.Sprintf("<b>Unencrypted Communication</b> named <b>Test Communication Link</b> between <b>Source Technical Asset</b> and <b>Target Technical Asset</b>%s", testCase.expectedSuffixTitle)
				assert.Equal(t, risks[0].Title, expectedMessage)
			} else {
				assert.Empty(t, risks)
			}
		})
	}
}
