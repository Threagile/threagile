/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseTrustBoundaryTest struct {
	input         string
	expected      TrustBoundaryType
	expectedError error
}

func TestParseTrustBoundaryType(t *testing.T) {
	testCases := map[string]ParseTrustBoundaryTest{
		"network-on-prem": {
			input:    "network-on-prem",
			expected: NetworkOnPrem,
		},
		"network-dedicated-hoster": {
			input:    "network-dedicated-hoster",
			expected: NetworkDedicatedHoster,
		},
		"network-virtual-lan": {
			input:    "network-virtual-lan",
			expected: NetworkVirtualLAN,
		},
		"network-cloud-provider": {
			input:    "network-cloud-provider",
			expected: NetworkCloudProvider,
		},
		"network-cloud-security-group": {
			input:    "network-cloud-security-group",
			expected: NetworkCloudSecurityGroup,
		},
		"network-policy-namespace-isolation": {
			input:    "network-policy-namespace-isolation",
			expected: NetworkPolicyNamespaceIsolation,
		},
		"execution-environment": {
			input:    "execution-environment",
			expected: ExecutionEnvironment,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseTrustBoundary(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
