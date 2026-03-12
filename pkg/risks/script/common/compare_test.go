package common

import (
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

func TestCompare_EqualStrings(t *testing.T) {
	a := SomeStringValue("hello", nil)
	b := SomeStringValue("hello", nil)

	event, err := Compare(a, b, "")
	assert.NoError(t, err)
	assert.True(t, IsSame(event.Property))
}

func TestCompare_DifferentStrings(t *testing.T) {
	a := SomeStringValue("hello", nil)
	b := SomeStringValue("world", nil)

	event, err := Compare(a, b, "")
	assert.NoError(t, err)
	assert.False(t, IsSame(event.Property))
}

func TestCompare_EqualBools(t *testing.T) {
	a := SomeBoolValue(true, nil)
	b := SomeBoolValue(true, nil)

	event, err := Compare(a, b, "")
	assert.NoError(t, err)
	assert.True(t, IsSame(event.Property))
}

func TestCompare_DifferentBools(t *testing.T) {
	a := SomeBoolValue(true, nil)
	b := SomeBoolValue(false, nil)

	event, err := Compare(a, b, "")
	assert.NoError(t, err)
	assert.False(t, IsSame(event.Property))
}

func TestCompare_Decimals_Less(t *testing.T) {
	a := SomeDecimalValue(decimal.NewFromInt(1), nil)
	b := SomeDecimalValue(decimal.NewFromInt(2), nil)

	event, err := Compare(a, b, "")
	assert.NoError(t, err)
	assert.True(t, IsLess(event.Property))
	assert.False(t, IsSame(event.Property))
	assert.False(t, IsGreater(event.Property))
}

func TestCompare_Decimals_Equal(t *testing.T) {
	a := SomeDecimalValue(decimal.NewFromInt(5), nil)
	b := SomeDecimalValue(decimal.NewFromInt(5), nil)

	event, err := Compare(a, b, "")
	assert.NoError(t, err)
	assert.True(t, IsSame(event.Property))
	assert.False(t, IsLess(event.Property))
	assert.False(t, IsGreater(event.Property))
}

func TestCompare_Decimals_Greater(t *testing.T) {
	a := SomeDecimalValue(decimal.NewFromInt(10), nil)
	b := SomeDecimalValue(decimal.NewFromInt(3), nil)

	event, err := Compare(a, b, "")
	assert.NoError(t, err)
	assert.True(t, IsGreater(event.Property))
	assert.False(t, IsSame(event.Property))
	assert.False(t, IsLess(event.Property))
}

func TestCompare_WithCastConfidentiality(t *testing.T) {
	a := SomeStringValue("confidential", nil)
	b := SomeStringValue("restricted", nil)

	event, err := Compare(a, b, "confidentiality")
	assert.NoError(t, err)
	assert.True(t, IsGreater(event.Property), "confidential (3) should be greater than restricted (2)")
}

func TestCompare_NilWithEmptyString(t *testing.T) {
	b := SomeStringValue("", nil)

	event, err := Compare(nil, b, "")
	assert.NoError(t, err)
	assert.True(t, IsSame(event.Property))
}

func TestCompare_NilWithFalse(t *testing.T) {
	b := SomeBoolValue(false, nil)

	event, err := Compare(nil, b, "")
	assert.NoError(t, err)
	assert.True(t, IsSame(event.Property))
}

func TestCompare_NilWithZeroDecimal(t *testing.T) {
	b := SomeDecimalValue(decimal.Zero, nil)

	event, err := Compare(nil, b, "")
	assert.NoError(t, err)
	assert.True(t, IsSame(event.Property))
}

func TestCompare_NilWithNil(t *testing.T) {
	// Compare nil with nil panics due to NewEqualProperty(nil) calling nil.Event()
	// This documents the current behavior as a known limitation
	assert.Panics(t, func() {
		_, _ = Compare(nil, nil, "")
	})
}

func TestIsSame_NilProperty(t *testing.T) {
	assert.False(t, IsSame(nil))
}

func TestIsGreater_NilProperty(t *testing.T) {
	assert.False(t, IsGreater(nil))
}

func TestIsLess_NilProperty(t *testing.T) {
	assert.False(t, IsLess(nil))
}
