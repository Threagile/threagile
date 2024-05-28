package common

import (
	"fmt"
	"github.com/shopspring/decimal"
)

type AnyValue struct {
	value   any
	history History
}

func (what AnyValue) Value() any {
	return what.value
}

func (what AnyValue) History() History {
	return what.history
}

func (what AnyValue) PlainValue() any {
	switch castValue := what.value.(type) {
	case Value:
		return castValue.PlainValue()
	}

	return what.value
}

func NilValue() Value {
	return &AnyValue{}
}

func SomeValue(anyValue any, history History) Value {
	if history == nil {
		history = NewHistory("")
	}

	switch castValue := anyValue.(type) {
	case string:
		return SomeStringValue(castValue, history)

	case fmt.Stringer:
		return SomeStringValue(castValue.String(), history)

	case bool:
		return SomeBoolValue(castValue, history)

	case decimal.Decimal:
		return SomeDecimalValue(castValue, history)

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), history)

	case int8:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), history)

	case int16:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), history)

	case int32:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), history)

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), history)

	case float32:
		return SomeDecimalValue(decimal.NewFromFloat32(castValue), history)

	case float64:
		return SomeDecimalValue(decimal.NewFromFloat(castValue), history)

	case []Value:
		return SomeArrayValue(castValue, history)

	case []any:
		array := make([]Value, 0)
		for _, item := range castValue {
			switch castItem := item.(type) {
			case Value:
				array = append(array, castItem)

			default:
				array = append(array, SomeValue(castItem, nil))
			}
		}

		return SomeArrayValue(array, history)

	case Value:
		return SomeValue(castValue.Value(), history.From(castValue.History()))

	case map[string]any:
		return &AnyValue{
			value:   anyValue,
			history: history,
		}

	case nil:
		return &AnyValue{
			history: history,
		}
	}

	return &AnyValue{
		value:   anyValue,
		history: history,
	}
}
