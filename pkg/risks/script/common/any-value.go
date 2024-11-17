package common

import (
	"fmt"
	"github.com/shopspring/decimal"
)

type AnyValue struct {
	value any
	name  Path
	event *Event
}

func (what AnyValue) Value() any {
	return what.value
}

func (what AnyValue) Name() Path {
	return what.name
}

func (what AnyValue) SetName(name ...string) {
	what.name.SetPath(name...)
}

func (what AnyValue) Event() *Event {
	return what.event
}

func (what AnyValue) PlainValue() any {
	switch castValue := what.value.(type) {
	case Value:
		return castValue.PlainValue()
	}

	return what.value
}

func (what AnyValue) Text() []string {
	switch castValue := what.value.(type) {
	case []any:
		text := make([]string, 0)
		for _, item := range castValue {
			text = append(text, fmt.Sprintf("  - %v", item))
		}

		return text

	case map[string]any:
		text := make([]string, 0)
		for name, item := range castValue {
			text = append(text, fmt.Sprintf("  %v: %v", name, item))
		}

		return text
	}

	return []string{fmt.Sprintf("%v", what.PlainValue())}
}

func NilValue() Value {
	return &AnyValue{}
}

func SomeValue(anyValue any, event *Event) Value {
	switch castValue := anyValue.(type) {
	case string:
		return SomeStringValue(castValue, event)

	case bool:
		return SomeBoolValue(castValue, event)

	case decimal.Decimal:
		return SomeDecimalValue(castValue, event)

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), event)

	case int8:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), event)

	case int16:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), event)

	case int32:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), event)

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), event)

	case float32:
		return SomeDecimalValue(decimal.NewFromFloat32(castValue), event)

	case float64:
		return SomeDecimalValue(decimal.NewFromFloat(castValue), event)

	case []Value:
		return SomeArrayValue(castValue, event)

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

		return SomeArrayValue(array, event)

	case Value:
		return castValue
	}

	return &AnyValue{
		value: anyValue,
		event: event,
	}
}

func AddValueHistory(anyValue Value, history []*Event) Value {
	if anyValue == nil {
		if len(history) == 0 {
			return nil
		}

		return SomeValue(nil, NewEvent(NewValueProperty(nil), EmptyPath()).AddHistory(history))
	}

	event := anyValue.Event()
	if event == nil {
		path := anyValue.Name()
		event = NewEvent(NewValueProperty(anyValue), &path).AddHistory(history)
	}

	return SomeValue(anyValue.PlainValue(), event)
}
