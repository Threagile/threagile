/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseConfidentialityTest struct {
	input         string
	expected      Confidentiality
	expectedError error
}

func TestParseConfidenitality(t *testing.T) {
	testCases := map[string]ParseConfidentialityTest{
		"public": {
			input:    "public",
			expected: Public,
		},
		"internal": {
			input:    "internal",
			expected: Internal,
		},
		"restricted": {
			input:    "restricted",
			expected: Restricted,
		},
		"confidential": {
			input:    "confidential",
			expected: Confidential,
		},
		"strictly-confidential": {
			input:    "strictly-confidential",
			expected: StrictlyConfidential,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseConfidentiality(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
