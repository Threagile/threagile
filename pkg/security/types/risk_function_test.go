/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseRiskFunctionTest struct {
	input         string
	expected      RiskFunction
	expectedError error
}

func TestParseRiskFunction(t *testing.T) {
	testCases := map[string]ParseRiskFunctionTest{
		"business-side": {
			input:    "business-side",
			expected: BusinessSide,
		},
		"architecture": {
			input:    "architecture",
			expected: Architecture,
		},
		"development": {
			input:    "development",
			expected: Development,
		},
		"operations": {
			input:    "operations",
			expected: Operations,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseRiskFunction(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
