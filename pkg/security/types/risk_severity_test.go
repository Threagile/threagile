/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseRiskSeverityTest struct {
	input         string
	expected      RiskSeverity
	expectedError error
}

func TestParseRiskSeverity(t *testing.T) {
	testCases := map[string]ParseRiskSeverityTest{
		"low": {
			input:    "low",
			expected: LowSeverity,
		},
		"medium": {
			input:    "medium",
			expected: MediumSeverity,
		},
		"elevated": {
			input:    "elevated",
			expected: ElevatedSeverity,
		},
		"high": {
			input:    "high",
			expected: HighSeverity,
		},
		"critical": {
			input:    "critical",
			expected: CriticalSeverity,
		},
		"default": {
			input:    "",
			expected: MediumSeverity,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseRiskSeverity(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
