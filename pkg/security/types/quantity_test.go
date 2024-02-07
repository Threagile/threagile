/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseQuantityTest struct {
	input         string
	expected      Quantity
	expectedError error
}

func TestParseQuantity(t *testing.T) {
	testCases := map[string]ParseQuantityTest{
		"very-few": {
			input:    "very-few",
			expected: VeryFew,
		},
		"few": {
			input:    "few",
			expected: Few,
		},
		"many": {
			input:    "many",
			expected: Many,
		},
		"very-many": {
			input:    "very-many",
			expected: VeryMany,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseQuantity(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
