package common

import (
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

func TestValues_Copy_Empty(t *testing.T) {
	v := Values{}
	copied, err := v.Copy()

	assert.NoError(t, err)
	assert.Empty(t, copied)
}

func TestValues_Copy_StringValue(t *testing.T) {
	v := Values{
		"name": SomeStringValue("hello", nil),
	}

	copied, err := v.Copy()
	assert.NoError(t, err)
	assert.Equal(t, "hello", copied["name"].Value())

	// verify independence
	v["name"] = SomeStringValue("changed", nil)
	assert.Equal(t, "hello", copied["name"].Value())
}

func TestValues_Copy_BoolValue(t *testing.T) {
	v := Values{
		"flag": SomeBoolValue(true, nil),
	}

	copied, err := v.Copy()
	assert.NoError(t, err)
	assert.Equal(t, true, copied["flag"].Value())
}

func TestValues_Copy_DecimalValue(t *testing.T) {
	v := Values{
		"num": SomeDecimalValue(decimal.NewFromInt(42), nil),
	}

	copied, err := v.Copy()
	assert.NoError(t, err)
	assert.True(t, decimal.NewFromInt(42).Equal(copied["num"].Value().(decimal.Decimal)))
}

func TestValues_Copy_ArrayValue(t *testing.T) {
	v := Values{
		"arr": SomeArrayValue([]Value{SomeStringValue("a", nil)}, nil),
	}

	copied, err := v.Copy()
	assert.NoError(t, err)

	arr, ok := copied["arr"].(*ArrayValue)
	assert.True(t, ok)
	assert.Len(t, arr.ArrayValue(), 1)
}

func TestValues_Copy_AnyValue(t *testing.T) {
	v := Values{
		"any": &AnyValue{value: map[string]any{"k": "v"}},
	}

	copied, err := v.Copy()
	assert.NoError(t, err)
	assert.NotNil(t, copied["any"])
}
