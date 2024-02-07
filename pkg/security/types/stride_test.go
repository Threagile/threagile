/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseStrideTest struct {
	input         string
	expected      STRIDE
	expectedError error
}

func TestParseStride(t *testing.T) {
	testCases := map[string]ParseStrideTest{
		"spoofing": {
			input:    "spoofing",
			expected: Spoofing,
		},
		"tampering": {
			input:    "tampering",
			expected: Tampering,
		},
		"repudiation": {
			input:    "repudiation",
			expected: Repudiation,
		},
		"information-disclosure": {
			input:    "information-disclosure",
			expected: InformationDisclosure,
		},
		"denial-of-service": {
			input:    "denial-of-service",
			expected: DenialOfService,
		},
		"elevation-of-privilege": {
			input:    "elevation-of-privilege",
			expected: ElevationOfPrivilege,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseSTRIDE(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
