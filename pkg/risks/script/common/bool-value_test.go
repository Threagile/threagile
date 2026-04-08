package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmptyBoolValue(t *testing.T) {
	v := EmptyBoolValue()
	assert.NotNil(t, v)
	assert.Equal(t, false, v.BoolValue())
	assert.Nil(t, v.Event())
}

func TestSomeBoolValue_True(t *testing.T) {
	v := SomeBoolValue(true, nil)
	assert.NotNil(t, v)
	assert.Equal(t, true, v.BoolValue())
	assert.Nil(t, v.Event())
}

func TestSomeBoolValue_False(t *testing.T) {
	v := SomeBoolValue(false, nil)
	assert.Equal(t, false, v.BoolValue())
}

func TestSomeBoolValueWithEvent(t *testing.T) {
	event := NewEvent(NewValueProperty(true), EmptyPath())
	v := SomeBoolValue(true, event)
	assert.Same(t, event, v.Event())
}

func TestBoolValue_Value(t *testing.T) {
	v := SomeBoolValue(true, nil)
	assert.Equal(t, true, v.Value())
}

func TestBoolValue_PlainValue(t *testing.T) {
	v := SomeBoolValue(false, nil)
	assert.Equal(t, false, v.PlainValue())
}

func TestBoolValue_Text_True(t *testing.T) {
	v := SomeBoolValue(true, nil)
	text := v.Text()
	assert.Equal(t, []string{"true"}, text)
}

func TestBoolValue_Text_False(t *testing.T) {
	v := SomeBoolValue(false, nil)
	text := v.Text()
	assert.Equal(t, []string{"false"}, text)
}

func TestBoolValue_Name(t *testing.T) {
	v := EmptyBoolValue()
	name := v.Name()
	assert.Nil(t, name.Path)
}

func TestToBoolValue_Success(t *testing.T) {
	original := SomeBoolValue(true, nil)
	converted, err := ToBoolValue(original)
	assert.NoError(t, err)
	assert.Equal(t, true, converted.BoolValue())
}

func TestToBoolValue_Error(t *testing.T) {
	original := SomeStringValue("notabool", nil)
	converted, err := ToBoolValue(original)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected value-expression to eval to a bool")
	assert.NotNil(t, converted)
	assert.Equal(t, false, converted.BoolValue())
}
