/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseTechnicalAssetTypeTest struct {
	input         string
	expected      TechnicalAssetType
	expectedError error
}

func TestParseTechnicalAssetType(t *testing.T) {
	testCases := map[string]ParseTechnicalAssetTypeTest{
		"external-entity": {
			input:    "external-entity",
			expected: ExternalEntity,
		},
		"process": {
			input:    "process",
			expected: Process,
		},
		"datastore": {
			input:    "datastore",
			expected: Datastore,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseTechnicalAssetType(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
