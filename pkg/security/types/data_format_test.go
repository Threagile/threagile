/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseDataFormatTest struct {
	input         string
	expected      DataFormat
	expectedError error
}

func TestParseDataFormat(t *testing.T) {
	testCases := map[string]ParseDataFormatTest{
		"json": {
			input:    "json",
			expected: JSON,
		},
		"xml": {
			input:    "xml",
			expected: XML,
		},
		"serialization": {
			input:    "serialization",
			expected: Serialization,
		},
		"file": {
			input:    "file",
			expected: File,
		},
		"csv": {
			input:    "csv",
			expected: CSV,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseDataFormat(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
