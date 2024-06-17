/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseTechnicalAssetMachineTest struct {
	input         string
	expected      TechnicalAssetMachine
	expectedError error
}

func TestParseTechnicalAssetMachine(t *testing.T) {
	testCases := map[string]ParseTechnicalAssetMachineTest{
		"physical": {
			input:    "physical",
			expected: Physical,
		},
		"virtual": {
			input:    "virtual",
			expected: Virtual,
		},
		"container": {
			input:    "container",
			expected: Container,
		},
		"serverless": {
			input:    "serverless",
			expected: Serverless,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseTechnicalAssetMachine(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
