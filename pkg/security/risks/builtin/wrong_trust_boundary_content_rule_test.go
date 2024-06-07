package builtin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/security/types"
)

func TestWrongTrustBoundaryContentRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewWrongTrustBoundaryContentRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type WrongTrustBoundaryContentRuleTest struct {
	tbType  types.TrustBoundaryType
	machine types.TechnicalAssetMachine

	riskCreated bool
}

func TestWrongTrustBoundaryContentRuleSendDataAssetRisksCreated(t *testing.T) {
	testCases := map[string]WrongTrustBoundaryContentRuleTest{
		"NetworkOnPrem": {
			tbType:      types.NetworkOnPrem,
			riskCreated: false,
		},
		"NetworkDedicatedHoster": {
			tbType:      types.NetworkDedicatedHoster,
			riskCreated: false,
		},
		"NetworkVirtualLAN": {
			tbType:      types.NetworkVirtualLAN,
			riskCreated: false,
		},
		"NetworkCloudProvider": {
			tbType:      types.NetworkCloudProvider,
			riskCreated: false,
		},
		"NetworkCloudSecurityGroup": {
			tbType:      types.NetworkCloudSecurityGroup,
			riskCreated: false,
		},
		"ExecutionEnvironment": {
			tbType:      types.ExecutionEnvironment,
			riskCreated: false,
		},
		"container": {
			tbType:      types.NetworkPolicyNamespaceIsolation,
			machine:     types.Container,
			riskCreated: false,
		},
		"serverless": {
			tbType:      types.NetworkPolicyNamespaceIsolation,
			machine:     types.Serverless,
			riskCreated: false,
		},
		"virtual": {
			tbType:      types.NetworkPolicyNamespaceIsolation,
			machine:     types.Virtual,
			riskCreated: true,
		},
		"physical": {
			tbType:      types.NetworkPolicyNamespaceIsolation,
			machine:     types.Physical,
			riskCreated: true,
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewWrongTrustBoundaryContentRule()
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta": {
						Id:      "ta",
						Title:   "Test Technical Asset",
						Machine: testCase.machine,
					},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{
					"tb1": {
						Type:                  testCase.tbType,
						TechnicalAssetsInside: []string{"ta"},
					},
				},
			})

			assert.Nil(t, err)
			if testCase.riskCreated {
				assert.Len(t, risks, 1)
				assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
				expTitle := fmt.Sprintf("<b>Wrong Trust Boundary Content</b> (non-container asset inside container trust boundary) at <b>%s</b>", "Test Technical Asset")
				assert.Equal(t, expTitle, risks[0].Title)
			} else {
				assert.Empty(t, risks)
			}
		})
	}
}
