package common

import (
	"fmt"
)

type StringValue struct {
	value   string
	history History
}

func (what StringValue) Value() any {
	return what.value
}

func (what StringValue) History() History {
	return what.history
}

func (what StringValue) PlainValue() any {
	return what.value
}

func (what StringValue) StringValue() string {
	return what.value
}

func EmptyStringValue() *StringValue {
	return &StringValue{}
}

func SomeStringValue(value string, history History) *StringValue {
	if history == nil {
		history = NewHistory("")
	}

	return &StringValue{
		value:   value,
		history: history,
	}
}

func ToStringValue(value Value) (*StringValue, error) {
	castValue, ok := value.Value().(string)

	var conversionError error
	if !ok {
		conversionError = fmt.Errorf("expected value-expression to eval to a string instead of %T", value.Value)
	}

	return &StringValue{
		history: value.History(),
		value:   castValue,
	}, conversionError
}
