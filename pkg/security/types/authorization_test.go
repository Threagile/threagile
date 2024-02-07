/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseAuthorizationTest struct {
	input         string
	expected      Authorization
	expectedError error
}

func TestParseAuthorization(t *testing.T) {
	testCases := map[string]ParseAuthorizationTest{
		"none": {
			input:    "none",
			expected: NoneAuthorization,
		},
		"technical-user": {
			input:    "technical-user",
			expected: TechnicalUser,
		},
		"enduser-identity-propagation": {
			input:    "enduser-identity-propagation",
			expected: EndUserIdentityPropagation,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseAuthorization(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
