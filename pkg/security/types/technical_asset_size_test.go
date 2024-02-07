/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseTechnicalAssetSizeTest struct {
	input         string
	expected      TechnicalAssetSize
	expectedError error
}

func TestParseTechnicalAssetSize(t *testing.T) {
	testCases := map[string]ParseTechnicalAssetSizeTest{
		"service": {
			input:    "service",
			expected: Service,
		},
		"system": {
			input:    "system",
			expected: System,
		},
		"application": {
			input:    "application",
			expected: Application,
		},
		"component": {
			input:    "component",
			expected: Component,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseTechnicalAssetSize(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
