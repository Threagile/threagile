package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmptyStringValue(t *testing.T) {
	v := EmptyStringValue()
	assert.NotNil(t, v)
	assert.Equal(t, "", v.StringValue())
	assert.Nil(t, v.Event())
}

func TestSomeStringValue(t *testing.T) {
	v := SomeStringValue("hello", nil)
	assert.NotNil(t, v)
	assert.Equal(t, "hello", v.StringValue())
	assert.Nil(t, v.Event())
}

func TestSomeStringValueWithEvent(t *testing.T) {
	event := NewEvent(NewValueProperty("test"), EmptyPath())
	v := SomeStringValue("world", event)
	assert.Equal(t, "world", v.StringValue())
	assert.Same(t, event, v.Event())
}

func TestStringValue_Value(t *testing.T) {
	v := SomeStringValue("hello", nil)
	assert.Equal(t, "hello", v.Value())
}

func TestStringValue_PlainValue(t *testing.T) {
	v := SomeStringValue("hello", nil)
	assert.Equal(t, "hello", v.PlainValue())
}

func TestStringValue_Text(t *testing.T) {
	v := SomeStringValue("hello", nil)
	text := v.Text()
	assert.Equal(t, []string{"hello"}, text)
}

func TestStringValue_TextEmpty(t *testing.T) {
	v := EmptyStringValue()
	text := v.Text()
	assert.Equal(t, []string{""}, text)
}

func TestStringValue_Name(t *testing.T) {
	v := EmptyStringValue()
	name := v.Name()
	assert.Nil(t, name.Path)
}

func TestStringValue_SetName(t *testing.T) {
	v := SomeStringValue("hello", nil)
	// SetName is on a value receiver, so it won't modify the original struct.
	// This tests that calling SetName does not panic.
	v.SetName("foo", "bar")
}

func TestToStringValue_Success(t *testing.T) {
	original := SomeStringValue("test", nil)
	converted, err := ToStringValue(original)
	assert.NoError(t, err)
	assert.Equal(t, "test", converted.StringValue())
}

func TestToStringValue_Error(t *testing.T) {
	original := SomeBoolValue(true, nil)
	converted, err := ToStringValue(original)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected value-expression to eval to a string")
	// Even on error, a StringValue is returned (with zero value)
	assert.NotNil(t, converted)
	assert.Equal(t, "", converted.StringValue())
}
