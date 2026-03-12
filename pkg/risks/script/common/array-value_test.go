package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmptyArrayValue(t *testing.T) {
	v := EmptyArrayValue()
	assert.NotNil(t, v)
	assert.Nil(t, v.ArrayValue())
	assert.Nil(t, v.Event())
}

func TestSomeArrayValue(t *testing.T) {
	items := []Value{
		SomeStringValue("a", nil),
		SomeStringValue("b", nil),
	}
	v := SomeArrayValue(items, nil)
	assert.NotNil(t, v)
	assert.Len(t, v.ArrayValue(), 2)
	assert.Nil(t, v.Event())
}

func TestSomeArrayValueWithEvent(t *testing.T) {
	event := NewEvent(NewValueProperty(nil), EmptyPath())
	items := []Value{SomeBoolValue(true, nil)}
	v := SomeArrayValue(items, event)
	assert.Same(t, event, v.Event())
}

func TestArrayValue_Value(t *testing.T) {
	items := []Value{SomeStringValue("x", nil)}
	v := SomeArrayValue(items, nil)
	result, ok := v.Value().([]Value)
	assert.True(t, ok)
	assert.Len(t, result, 1)
}

func TestArrayValue_PlainValue(t *testing.T) {
	items := []Value{
		SomeStringValue("a", nil),
		SomeBoolValue(true, nil),
	}
	v := SomeArrayValue(items, nil)
	plain, ok := v.PlainValue().([]any)
	assert.True(t, ok)
	assert.Len(t, plain, 2)
	assert.Equal(t, "a", plain[0])
	assert.Equal(t, true, plain[1])
}

func TestArrayValue_PlainValueEmpty(t *testing.T) {
	v := SomeArrayValue([]Value{}, nil)
	plain, ok := v.PlainValue().([]any)
	assert.True(t, ok)
	assert.Empty(t, plain)
}

func TestArrayValue_Text_SingleLineItems(t *testing.T) {
	items := []Value{
		SomeStringValue("first", nil),
		SomeStringValue("second", nil),
	}
	v := SomeArrayValue(items, nil)
	text := v.Text()
	assert.Equal(t, []string{"  - first", "  - second"}, text)
}

func TestArrayValue_Text_Empty(t *testing.T) {
	v := SomeArrayValue([]Value{}, nil)
	text := v.Text()
	assert.Empty(t, text)
}

func TestArrayValue_Name(t *testing.T) {
	v := EmptyArrayValue()
	name := v.Name()
	assert.Nil(t, name.Path)
}

func TestToArrayValue_FromValueSlice(t *testing.T) {
	items := []Value{
		SomeStringValue("a", nil),
		SomeStringValue("b", nil),
	}
	wrapper := SomeArrayValue(items, nil)
	converted, err := ToArrayValue(wrapper)
	assert.NoError(t, err)
	assert.Len(t, converted.ArrayValue(), 2)
}

func TestToArrayValue_FromAnySlice(t *testing.T) {
	// Create an AnyValue wrapping []any
	anySlice := []any{"hello", true}
	wrapper := &AnyValue{value: anySlice}
	converted, err := ToArrayValue(wrapper)
	assert.NoError(t, err)
	assert.Len(t, converted.ArrayValue(), 2)
}

func TestToArrayValue_Error(t *testing.T) {
	original := SomeStringValue("notanarray", nil)
	converted, err := ToArrayValue(original)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected value-expression to eval to an array")
	assert.Nil(t, converted)
}
