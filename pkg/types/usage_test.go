/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseUsageTest struct {
	input         string
	expected      Usage
	expectedError error
}

func TestParseUsage(t *testing.T) {
	testCases := map[string]ParseUsageTest{
		"business": {
			input:    "business",
			expected: Business,
		},
		"devops": {
			input:    "devops",
			expected: DevOps,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseUsage(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
