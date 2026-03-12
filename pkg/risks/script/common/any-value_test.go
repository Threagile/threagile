package common

import (
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

func TestSomeValue_String(t *testing.T) {
	v := SomeValue("hello", nil)
	_, ok := v.(*StringValue)
	assert.True(t, ok)
	assert.Equal(t, "hello", v.Value())
}

func TestSomeValue_Bool(t *testing.T) {
	v := SomeValue(true, nil)
	_, ok := v.(*BoolValue)
	assert.True(t, ok)
	assert.Equal(t, true, v.Value())
}

func TestSomeValue_Int(t *testing.T) {
	v := SomeValue(42, nil)
	dv, ok := v.(*DecimalValue)
	assert.True(t, ok)
	assert.True(t, dv.DecimalValue().Equal(decimal.NewFromInt(42)))
}

func TestSomeValue_Int8(t *testing.T) {
	v := SomeValue(int8(8), nil)
	dv, ok := v.(*DecimalValue)
	assert.True(t, ok)
	assert.True(t, dv.DecimalValue().Equal(decimal.NewFromInt(8)))
}

func TestSomeValue_Int16(t *testing.T) {
	v := SomeValue(int16(16), nil)
	dv, ok := v.(*DecimalValue)
	assert.True(t, ok)
	assert.True(t, dv.DecimalValue().Equal(decimal.NewFromInt(16)))
}

func TestSomeValue_Int32(t *testing.T) {
	v := SomeValue(int32(32), nil)
	dv, ok := v.(*DecimalValue)
	assert.True(t, ok)
	assert.True(t, dv.DecimalValue().Equal(decimal.NewFromInt(32)))
}

func TestSomeValue_Int64(t *testing.T) {
	v := SomeValue(int64(64), nil)
	dv, ok := v.(*DecimalValue)
	assert.True(t, ok)
	assert.True(t, dv.DecimalValue().Equal(decimal.NewFromInt(64)))
}

func TestSomeValue_Float32(t *testing.T) {
	v := SomeValue(float32(1.5), nil)
	dv, ok := v.(*DecimalValue)
	assert.True(t, ok)
	assert.True(t, dv.DecimalValue().Equal(decimal.NewFromFloat32(1.5)))
}

func TestSomeValue_Float64(t *testing.T) {
	v := SomeValue(float64(2.5), nil)
	dv, ok := v.(*DecimalValue)
	assert.True(t, ok)
	assert.True(t, dv.DecimalValue().Equal(decimal.NewFromFloat(2.5)))
}

func TestSomeValue_Decimal(t *testing.T) {
	d := decimal.NewFromInt(99)
	v := SomeValue(d, nil)
	dv, ok := v.(*DecimalValue)
	assert.True(t, ok)
	assert.True(t, dv.DecimalValue().Equal(d))
}

func TestSomeValue_ValueSlice(t *testing.T) {
	items := []Value{SomeStringValue("a", nil)}
	v := SomeValue(items, nil)
	av, ok := v.(*ArrayValue)
	assert.True(t, ok)
	assert.Len(t, av.ArrayValue(), 1)
}

func TestSomeValue_AnySlice(t *testing.T) {
	items := []any{"x", 10, true}
	v := SomeValue(items, nil)
	av, ok := v.(*ArrayValue)
	assert.True(t, ok)
	assert.Len(t, av.ArrayValue(), 3)

	// Each element should be wrapped appropriately
	assert.IsType(t, &StringValue{}, av.ArrayValue()[0])
	assert.IsType(t, &DecimalValue{}, av.ArrayValue()[1])
	assert.IsType(t, &BoolValue{}, av.ArrayValue()[2])
}

func TestSomeValue_ExistingValue(t *testing.T) {
	original := SomeStringValue("keep", nil)
	v := SomeValue(original, nil)
	assert.Same(t, original, v)
}

func TestSomeValue_Nil(t *testing.T) {
	v := SomeValue(nil, nil)
	_, ok := v.(*AnyValue)
	assert.True(t, ok)
	assert.Nil(t, v.Value())
}

func TestSomeValue_UnknownType(t *testing.T) {
	type custom struct{}
	v := SomeValue(custom{}, nil)
	_, ok := v.(*AnyValue)
	assert.True(t, ok)
}

func TestNilValue(t *testing.T) {
	v := NilValue()
	assert.NotNil(t, v)
	assert.Nil(t, v.Value())
}

func TestAnyValue_PlainValue_Nested(t *testing.T) {
	inner := SomeStringValue("nested", nil)
	outer := &AnyValue{value: inner}
	assert.Equal(t, "nested", outer.PlainValue())
}

func TestAnyValue_PlainValue_Plain(t *testing.T) {
	v := &AnyValue{value: 42}
	assert.Equal(t, 42, v.PlainValue())
}

func TestAnyValue_PlainValue_Nil(t *testing.T) {
	v := NilValue()
	assert.Nil(t, v.PlainValue())
}

func TestAnyValue_Text_Scalar(t *testing.T) {
	v := &AnyValue{value: 42}
	text := v.Text()
	assert.Equal(t, []string{"42"}, text)
}

func TestAnyValue_Text_NilValue(t *testing.T) {
	v := NilValue()
	text := v.Text()
	assert.Equal(t, []string{"<nil>"}, text)
}

func TestAddValueHistory_NilValueEmptyHistory(t *testing.T) {
	result := AddValueHistory(nil, []*Event{})
	assert.Nil(t, result)
}

func TestAddValueHistory_NilValueNonEmptyHistory(t *testing.T) {
	event := NewEvent(NewValueProperty("test"), EmptyPath())
	result := AddValueHistory(nil, []*Event{event})
	assert.NotNil(t, result)
	// The result wraps nil
	assert.Nil(t, result.PlainValue())
}

func TestAddValueHistory_WithValue(t *testing.T) {
	v := SomeStringValue("hello", nil)
	event := NewEvent(NewValueProperty("reason"), EmptyPath())
	result := AddValueHistory(v, []*Event{event})
	assert.NotNil(t, result)
	assert.Equal(t, "hello", result.PlainValue())
}

func TestAddValueHistory_WithValueAndExistingEvent(t *testing.T) {
	existingEvent := NewEvent(NewValueProperty("original"), EmptyPath())
	v := SomeStringValue("hello", existingEvent)
	historyEvent := NewEvent(NewValueProperty("reason"), EmptyPath())
	result := AddValueHistory(v, []*Event{historyEvent})
	assert.NotNil(t, result)
	assert.Equal(t, "hello", result.PlainValue())
}
