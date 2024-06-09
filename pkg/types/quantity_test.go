/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"

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
			expectedError: fmt.Errorf("unknown quantity value \"unknown\""),
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

type MarshalQuantityTest struct {
	input    Quantity
	expected string
}

func TestMarshal(t *testing.T) {
	testCases := map[string]MarshalQuantityTest{
		"very-few": {
			input:    VeryFew,
			expected: "very-few",
		},
		"few": {
			input:    Few,
			expected: "few",
		},
		"many": {
			input:    Many,
			expected: "many",
		},
		"very-many": {
			input:    VeryMany,
			expected: "very-many",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			var v struct {
				Quantity Quantity
			}
			v.Quantity = testCase.input

			bytes, err := yaml.Marshal(v)

			assert.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("quantity: %s\n", testCase.expected), string(bytes))

			jsonBytes, err := json.Marshal(v)
			assert.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("{\"Quantity\":\"%s\"}", testCase.expected), string(jsonBytes))
		})
	}
}

type UnmarshalQuantityTest struct {
	input    string
	expected Quantity
}

func TestUnmarshal(t *testing.T) {
	testCases := map[string]UnmarshalQuantityTest{
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
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			yamlString := fmt.Sprintf("quantity: %s\n", testCase.input)
			var v struct {
				Quantity Quantity
			}
			err := yaml.Unmarshal([]byte(yamlString), &v)

			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, v.Quantity)

			jsonString := fmt.Sprintf("{\"Quantity\":\"%s\"}", testCase.input)
			err = json.Unmarshal([]byte(jsonString), &v)

			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, v.Quantity)
		})
	}
}

func TestUnmarshallJsonError(t *testing.T) {
	var v struct {
		Quantity Quantity
	}
	err := json.Unmarshal([]byte("{\"Quantity\":\"unknown\"}"), &v)

	assert.Error(t, err)
}

func TestUnmarshallYamlError(t *testing.T) {
	var v struct {
		Quantity Quantity
	}
	err := yaml.Unmarshal([]byte("quantity: unknown\n"), &v)

	assert.Error(t, err)
}

func TestQuantityValues(t *testing.T) {
	assert.Equal(t, []TypeEnum{VeryFew, Few, Many, VeryMany}, QuantityValues())
}

func TestQuantityString(t *testing.T) {
	assert.Equal(t, "very-few", VeryFew.String())
	assert.Equal(t, "few", Few.String())
	assert.Equal(t, "many", Many.String())
	assert.Equal(t, "very-many", VeryMany.String())
}

func TestQuantityExplain(t *testing.T) {
	assert.Equal(t, "Very few", VeryFew.Explain())
	assert.Equal(t, "Few", Few.Explain())
	assert.Equal(t, "Many", Many.Explain())
	assert.Equal(t, "Very many", VeryMany.Explain())
}

func TestQuantityTitle(t *testing.T) {
	assert.Equal(t, "very few", VeryFew.Title())
	assert.Equal(t, "few", Few.Title())
	assert.Equal(t, "many", Many.Title())
	assert.Equal(t, "very many", VeryMany.Title())
}

func TestQuantityQuantityFactor(t *testing.T) {
	assert.Equal(t, float64(1), VeryFew.QuantityFactor())
	assert.Equal(t, float64(2), Few.QuantityFactor())
	assert.Equal(t, float64(3), Many.QuantityFactor())
	assert.Equal(t, float64(5), VeryMany.QuantityFactor())
}
