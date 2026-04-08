package common

import (
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

func TestCastValue_Confidentiality(t *testing.T) {
	val := SomeStringValue("confidential", nil)
	result, err := CastValue(val, "confidentiality")

	assert.NoError(t, err)
	// confidential is index 3
	assert.True(t, decimal.NewFromInt(3).Equal(result.Value().(decimal.Decimal)))
}

func TestCastValue_Criticality(t *testing.T) {
	val := SomeStringValue("critical", nil)
	result, err := CastValue(val, "criticality")

	assert.NoError(t, err)
	// critical is index 3
	assert.True(t, decimal.NewFromInt(3).Equal(result.Value().(decimal.Decimal)))
}

func TestCastValue_Impact(t *testing.T) {
	val := SomeStringValue("medium", nil)
	result, err := CastValue(val, "impact")

	assert.NoError(t, err)
	// medium is index 1
	assert.True(t, decimal.NewFromInt(1).Equal(result.Value().(decimal.Decimal)))
}

func TestCastValue_Likelihood(t *testing.T) {
	val := SomeStringValue("unlikely", nil)
	result, err := CastValue(val, "likelihood")

	assert.NoError(t, err)
	// unlikely is index 0
	assert.True(t, decimal.NewFromInt(0).Equal(result.Value().(decimal.Decimal)))
}

func TestCastValue_UnknownType(t *testing.T) {
	val := SomeStringValue("something", nil)
	_, err := CastValue(val, "unknown_type")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown cast type")
}

func TestCastValue_Nil(t *testing.T) {
	result, err := CastValue(nil, "confidentiality")

	assert.NoError(t, err)
	assert.Nil(t, result.Value())
}

func TestCastValue_IntPassthrough(t *testing.T) {
	// Use AnyValue wrapping an int, since CastValue switches on value.Value().(type)
	val := &AnyValue{value: 2}
	result, err := CastValue(val, "confidentiality")

	assert.NoError(t, err)
	assert.True(t, decimal.NewFromInt(2).Equal(result.Value().(decimal.Decimal)))
}
