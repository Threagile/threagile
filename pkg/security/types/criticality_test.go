/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseCriticalityTest struct {
	input         string
	expected      Criticality
	expectedError error
}

func TestParseCriticality(t *testing.T) {
	testCases := map[string]ParseCriticalityTest{
		"archive": {
			input:    "archive",
			expected: Archive,
		},
		"operational": {
			input:    "operational",
			expected: Operational,
		},
		"important": {
			input:    "important",
			expected: Important,
		},
		"critical": {
			input:    "critical",
			expected: Critical,
		},
		"mission-critical": {
			input:    "mission-critical",
			expected: MissionCritical,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseCriticality(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
