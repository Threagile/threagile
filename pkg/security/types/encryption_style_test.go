/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseEncryptionStyleTest struct {
	input         string
	expected      EncryptionStyle
	expectedError error
}

func TestParseEncryptionStyle(t *testing.T) {
	testCases := map[string]ParseEncryptionStyleTest{
		"none": {
			input:    "none",
			expected: NoneEncryption,
		},
		"transparent": {
			input:    "transparent",
			expected: Transparent,
		},
		"data-with-symmetric-shared-key": {
			input:    "data-with-symmetric-shared-key",
			expected: DataWithSymmetricSharedKey,
		},
		"data-with-asymmetric-shared-key": {
			input:    "data-with-asymmetric-shared-key",
			expected: DataWithAsymmetricSharedKey,
		},
		"data-with-enduser-individual-key": {
			input:    "data-with-enduser-individual-key",
			expected: DataWithEndUserIndividualKey,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseEncryptionStyle(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
