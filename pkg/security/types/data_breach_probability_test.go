/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseDataBreachProbabilityTest struct {
	input         string
	expected      DataBreachProbability
	expectedError error
}

func TestParseDataBreachProbability(t *testing.T) {
	testCases := map[string]ParseDataBreachProbabilityTest{
		"improbable": {
			input:    "improbable",
			expected: Improbable,
		},
		"possible": {
			input:    "possible",
			expected: Possible,
		},
		"probable": {
			input:    "probable",
			expected: Probable,
		},
		"default": {
			input:    "",
			expected: Possible,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseDataBreachProbability(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
