package builtin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
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

func TestWrongTrustBoundaryContentRuleNetworkPolicyNamespaceIsolationEmptyAssetsInsideNoRiskCreated(t *testing.T) {
	rule := NewWrongTrustBoundaryContentRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": {
				Id:                    "tb1",
				Type:                  types.NetworkPolicyNamespaceIsolation,
				TechnicalAssetsInside: []string{},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestWrongTrustBoundaryContentRuleNetworkPolicyNamespaceIsolationTwoContainersOneVirtualOneRiskCreated(t *testing.T) {
	rule := NewWrongTrustBoundaryContentRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"container1": {
				Id:      "container1",
				Title:   "Container Asset 1",
				Machine: types.Container,
			},
			"container2": {
				Id:      "container2",
				Title:   "Container Asset 2",
				Machine: types.Container,
			},
			"virtual1": {
				Id:      "virtual1",
				Title:   "Virtual Asset",
				Machine: types.Virtual,
			},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": {
				Id:                    "tb1",
				Type:                  types.NetworkPolicyNamespaceIsolation,
				TechnicalAssetsInside: []string{"container1", "container2", "virtual1"},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	expTitle := fmt.Sprintf("<b>Wrong Trust Boundary Content</b> (non-container asset inside container trust boundary) at <b>%s</b>", "Virtual Asset")
	assert.Equal(t, expTitle, risks[0].Title)
	assert.Equal(t, "virtual1", risks[0].MostRelevantTechnicalAssetId)
}

func TestWrongTrustBoundaryContentRuleNetworkPolicyNamespaceIsolationContainerServerlessPhysicalOneRiskCreated(t *testing.T) {
	rule := NewWrongTrustBoundaryContentRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"container1": {
				Id:      "container1",
				Title:   "Container Asset",
				Machine: types.Container,
			},
			"serverless1": {
				Id:      "serverless1",
				Title:   "Serverless Asset",
				Machine: types.Serverless,
			},
			"physical1": {
				Id:      "physical1",
				Title:   "Physical Asset",
				Machine: types.Physical,
			},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": {
				Id:                    "tb1",
				Type:                  types.NetworkPolicyNamespaceIsolation,
				TechnicalAssetsInside: []string{"container1", "serverless1", "physical1"},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	expTitle := fmt.Sprintf("<b>Wrong Trust Boundary Content</b> (non-container asset inside container trust boundary) at <b>%s</b>", "Physical Asset")
	assert.Equal(t, expTitle, risks[0].Title)
	assert.Equal(t, "physical1", risks[0].MostRelevantTechnicalAssetId)
}

func TestWrongTrustBoundaryContentRuleMultipleBoundariesOnlyNetworkPolicyOneRisksCreatedFromCorrectBoundary(t *testing.T) {
	rule := NewWrongTrustBoundaryContentRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"virtual-in-np": {
				Id:      "virtual-in-np",
				Title:   "Virtual In NetworkPolicy",
				Machine: types.Virtual,
			},
			"virtual-in-network": {
				Id:      "virtual-in-network",
				Title:   "Virtual In Network",
				Machine: types.Virtual,
			},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb-network-policy": {
				Id:                    "tb-network-policy",
				Type:                  types.NetworkPolicyNamespaceIsolation,
				TechnicalAssetsInside: []string{"virtual-in-np"},
			},
			"tb-network-onprem": {
				Id:                    "tb-network-onprem",
				Type:                  types.NetworkOnPrem,
				TechnicalAssetsInside: []string{"virtual-in-network"},
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	expTitle := fmt.Sprintf("<b>Wrong Trust Boundary Content</b> (non-container asset inside container trust boundary) at <b>%s</b>", "Virtual In NetworkPolicy")
	assert.Equal(t, expTitle, risks[0].Title)
	assert.Equal(t, "virtual-in-np", risks[0].MostRelevantTechnicalAssetId)
}
