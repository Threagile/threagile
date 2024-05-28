package common

import (
	"fmt"
)

type ArrayValue struct {
	value   []Value
	history History
}

func (what ArrayValue) Value() any {
	return what.value
}

func (what ArrayValue) History() History {
	return what.history
}

func (what ArrayValue) ArrayValue() []Value {
	return what.value
}

func (what ArrayValue) PlainValue() any {
	values := make([]any, 0)
	for _, value := range what.value {
		values = append(values, value.PlainValue())
	}

	return values
}

func EmptyArrayValue() *ArrayValue {
	return &ArrayValue{}
}

func SomeArrayValue(value []Value, history History) *ArrayValue {
	if history == nil {
		history = NewHistory("")
	}

	return &ArrayValue{
		value:   value,
		history: history,
	}
}

func ToArrayValue(value Value) (*ArrayValue, error) {
	castValue, ok := value.Value().([]Value)

	var conversionError error
	if !ok {
		conversionError = fmt.Errorf("expected value-expression to eval to an array instead of %T", value.Value)
	}

	return &ArrayValue{
		value:   castValue,
		history: value.History(),
	}, conversionError
}
