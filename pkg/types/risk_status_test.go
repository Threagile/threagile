/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseRiskStatusTest struct {
	input         string
	expected      RiskStatus
	expectedError error
}

func TestParseRiskStatus(t *testing.T) {
	testCases := map[string]ParseRiskStatusTest{
		"unchecked": {
			input:    "unchecked",
			expected: Unchecked,
		},
		"in-discussion": {
			input:    "in-discussion",
			expected: InDiscussion,
		},
		"accepted": {
			input:    "accepted",
			expected: Accepted,
		},
		"in-progress": {
			input:    "in-progress",
			expected: InProgress,
		},
		"mitigated": {
			input:    "mitigated",
			expected: Mitigated,
		},
		"false-positive": {
			input:    "false-positive",
			expected: FalsePositive,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseRiskStatus(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
