package common

import (
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

func TestEmptyDecimalValue(t *testing.T) {
	v := EmptyDecimalValue()
	assert.NotNil(t, v)
	assert.True(t, v.DecimalValue().Equal(decimal.Zero))
	assert.Nil(t, v.Event())
}

func TestSomeDecimalValue(t *testing.T) {
	d := decimal.NewFromInt(42)
	v := SomeDecimalValue(d, nil)
	assert.NotNil(t, v)
	assert.True(t, v.DecimalValue().Equal(d))
	assert.Nil(t, v.Event())
}

func TestSomeDecimalValueWithEvent(t *testing.T) {
	d := decimal.NewFromFloat(3.14)
	event := NewEvent(NewValueProperty(d), EmptyPath())
	v := SomeDecimalValue(d, event)
	assert.Same(t, event, v.Event())
}

func TestDecimalValue_Value(t *testing.T) {
	d := decimal.NewFromInt(42)
	v := SomeDecimalValue(d, nil)
	result, ok := v.Value().(decimal.Decimal)
	assert.True(t, ok)
	assert.True(t, result.Equal(d))
}

func TestDecimalValue_PlainValue(t *testing.T) {
	d := decimal.NewFromInt(100)
	v := SomeDecimalValue(d, nil)
	result, ok := v.PlainValue().(decimal.Decimal)
	assert.True(t, ok)
	assert.True(t, result.Equal(d))
}

func TestDecimalValue_Text(t *testing.T) {
	d := decimal.NewFromInt(42)
	v := SomeDecimalValue(d, nil)
	text := v.Text()
	assert.Equal(t, []string{"42"}, text)
}

func TestDecimalValue_TextFloat(t *testing.T) {
	d := decimal.NewFromFloat(3.14)
	v := SomeDecimalValue(d, nil)
	text := v.Text()
	assert.Equal(t, []string{"3.14"}, text)
}

func TestDecimalValue_Name(t *testing.T) {
	v := EmptyDecimalValue()
	name := v.Name()
	assert.Nil(t, name.Path)
}

func TestToDecimalValue_Success(t *testing.T) {
	d := decimal.NewFromInt(99)
	original := SomeDecimalValue(d, nil)
	converted, err := ToDecimalValue(original)
	assert.NoError(t, err)
	assert.True(t, converted.DecimalValue().Equal(d))
}

func TestToDecimalValue_Error(t *testing.T) {
	original := SomeStringValue("notadecimal", nil)
	converted, err := ToDecimalValue(original)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected value-expression to eval to a decimal")
	assert.NotNil(t, converted)
	assert.True(t, converted.DecimalValue().Equal(decimal.Zero))
}
