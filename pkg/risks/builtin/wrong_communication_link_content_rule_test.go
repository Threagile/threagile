package builtin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestWrongCommunicationLinkContentRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewWrongCommunicationLinkContentRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type WrongCommunicationLinkContentRuleTest struct {
	receiveAnyData    bool
	sendAnyData       bool
	readonly          bool
	protocol          types.Protocol
	isLibrary         bool
	isLocalFileSystem bool
	machine           types.TechnicalAssetMachine

	riskCreated    bool
	expectedReason string
}

func TestWrongCommunicationLinkContentRuleSendDataAssetRisksCreated(t *testing.T) {
	testCases := map[string]WrongCommunicationLinkContentRuleTest{
		"not readonly no data asset send no risk": {
			receiveAnyData: false,
			sendAnyData:    false,
			readonly:       false,
			protocol:       types.UnknownProtocol,

			riskCreated: false,
		},
		"not readonly data asset send no received no risk": {
			receiveAnyData: false,
			sendAnyData:    true,
			readonly:       false,
			protocol:       types.UnknownProtocol,

			riskCreated: false,
		},
		"not readonly data asset received no send risk": {
			receiveAnyData: true,
			sendAnyData:    false,
			readonly:       false,
			protocol:       types.UnknownProtocol,

			riskCreated:    true,
			expectedReason: "(data assets sent/received not matching the communication link's readonly flag)",
		},
		"not readonly data asset received and send no risk": {
			receiveAnyData: true,
			sendAnyData:    true,
			readonly:       false,
			protocol:       types.UnknownProtocol,

			riskCreated: false,
		},
		"readonly no data asset send no risk": {
			receiveAnyData: false,
			sendAnyData:    false,
			readonly:       true,
			protocol:       types.UnknownProtocol,

			riskCreated: false,
		},
		"readonly data asset send no received no risk": {
			receiveAnyData: false,
			sendAnyData:    true,
			readonly:       true,
			protocol:       types.UnknownProtocol,

			riskCreated:    true,
			expectedReason: "(data assets sent/received not matching the communication link's readonly flag)",
		},
		"readonly data asset received no send risk": {
			receiveAnyData: true,
			sendAnyData:    false,
			readonly:       true,
			protocol:       types.UnknownProtocol,

			riskCreated: false,
		},
		"readonly data asset received and send no risk": {
			receiveAnyData: true,
			sendAnyData:    true,
			readonly:       true,
			protocol:       types.UnknownProtocol,

			riskCreated: false,
		},
		"protocol type InProcessLibraryCall does not match target technology type Library": {
			receiveAnyData: false,
			sendAnyData:    false,
			readonly:       false,
			protocol:       types.InProcessLibraryCall,
			isLibrary:      false,

			riskCreated:    true,
			expectedReason: "(protocol type \"in-process-library-call\" does not match target technology type \"\": expected \"library\")",
		},
		"protocol type InProcessLibraryCall match target technology type Library": {
			receiveAnyData: false,
			sendAnyData:    false,
			readonly:       false,
			protocol:       types.InProcessLibraryCall,
			isLibrary:      true,

			riskCreated: false,
		},
		"protocol type LocalFileAccess does not match target technology type LocalFileSystem": {
			receiveAnyData:    false,
			sendAnyData:       false,
			readonly:          false,
			protocol:          types.LocalFileAccess,
			isLocalFileSystem: false,

			riskCreated:    true,
			expectedReason: "(protocol type \"local-file-access\" does not match target technology type \"\": expected \"local-file-system\")",
		},
		"protocol type LocalFileAccess match target technology type LocalFileSystem": {
			receiveAnyData:    false,
			sendAnyData:       false,
			readonly:          false,
			protocol:          types.LocalFileAccess,
			isLocalFileSystem: true,

			riskCreated: false,
		},
		"protocol type ContainerSpawning does not match target target machine type": {
			receiveAnyData: false,
			sendAnyData:    false,
			readonly:       false,
			protocol:       types.ContainerSpawning,
			machine:        types.Physical,

			riskCreated:    true,
			expectedReason: "(protocol type \"container-spawning\" does not match target machine type \"physical\": expected \"container\")",
		},
		"protocol type ContainerSpawning match target machine type Container": {
			receiveAnyData: false,
			sendAnyData:    false,
			readonly:       false,
			protocol:       types.ContainerSpawning,
			machine:        types.Container,

			riskCreated: false,
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewWrongCommunicationLinkContentRule()
			dataAssetsSend := []string{}
			if testCase.sendAnyData {
				dataAssetsSend = append(dataAssetsSend, "da1")
			}
			dataAssetsReceived := []string{}
			if testCase.receiveAnyData {
				dataAssetsReceived = append(dataAssetsReceived, "da1")
			}

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
								DataAssetsSent:     dataAssetsSend,
								DataAssetsReceived: dataAssetsReceived,
								Protocol:           testCase.protocol,
								Readonly:           testCase.readonly,
							},
						},
					},
					"target": {
						Id:      "target",
						Title:   "Target Technical Asset",
						Machine: testCase.machine,
						Technologies: types.TechnologyList{
							{
								Attributes: map[string]bool{
									types.Library:         testCase.isLibrary,
									types.LocalFileSystem: testCase.isLocalFileSystem,
								},
							},
						},
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"target": {
						{
							Title:              "Data Transfer",
							SourceId:           "source",
							TargetId:           "target",
							Protocol:           testCase.protocol,
							Readonly:           testCase.readonly,
							DataAssetsSent:     dataAssetsSend,
							DataAssetsReceived: dataAssetsReceived,
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
			if testCase.riskCreated {
				assert.Len(t, risks, 1)
				assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
				expTitle := fmt.Sprintf("<b>Wrong Communication Link Content</b> %s at <b>Source Technical Asset</b> regarding communication link <b>Data Transfer</b>", testCase.expectedReason)
				assert.Equal(t, expTitle, risks[0].Title)
			} else {
				assert.Empty(t, risks)
			}
		})
	}
}
