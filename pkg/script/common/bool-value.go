package common

import (
	"fmt"
)

type BoolValue struct {
	value   bool
	history History
}

func (what BoolValue) Value() any {
	return what.value
}

func (what BoolValue) History() History {
	return what.history
}

func (what BoolValue) PlainValue() any {
	return what.value
}

func (what BoolValue) BoolValue() bool {
	return what.value
}

func EmptyBoolValue() *BoolValue {
	return &BoolValue{}
}

func SomeBoolValue(value bool, history History) *BoolValue {
	if history == nil {
		history = NewHistory("")
	}

	return &BoolValue{
		value:   value,
		history: history,
	}
}

func ToBoolValue(value Value) (*BoolValue, error) {
	castValue, ok := value.Value().(bool)

	var conversionError error
	if !ok {
		conversionError = fmt.Errorf("expected value-expression to eval to a bool instead of %T", value.Value)
	}

	return &BoolValue{
		value:   castValue,
		history: value.History(),
	}, conversionError
}
