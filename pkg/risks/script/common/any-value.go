package common

import (
	"fmt"

	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/risks/script/event"
	"gopkg.in/yaml.v3"
)

type AnyValue struct {
	value   any
	path    event.Path
	history event.History
}

func (what AnyValue) PlainValue() any {
	switch castValue := what.value.(type) {
	case Value:
		return castValue.PlainValue()
	}

	return what.value
}

func (what AnyValue) Value() any {
	return what.value
}

func (what AnyValue) Path() event.Path {
	return what.path
}

func (what AnyValue) ValueText() event.Text {
	yamlText, yamlError := yaml.Marshal(what.value)
	if yamlError != nil {
		return new(event.Text).Append(fmt.Sprintf("%v", what.value))
	}

	return SomeStringValue(string(yamlText), nil).ValueText()
}

func (what AnyValue) History() event.History {
	return what.history
}

func (what AnyValue) Text() event.Text {
	if len(what.path) > 0 {
		return new(event.Text).Append(what.path.String())
	}

	return what.ValueText()
}

func (what AnyValue) Description() event.Text {
	if len(what.path) == 0 {
		return what.History().Text()
	}

	text := what.ValueText()
	switch len(text) {
	case 0:
		return new(event.Text).Append(what.path.String() + " is (empty)")

	case 1:
		return new(event.Text).Append(fmt.Sprintf("%v is %v", what.path.String(), text[0].Line))

	default:
		return new(event.Text).Append(fmt.Sprintf("%v is:", what.path.String()), text...)
	}
}

func NilValue() Value {
	return &AnyValue{}
}

func SomeValue(anyValue any, stack Stack, events ...event.Event) Value {
	return SomeValueWithPath(anyValue, nil, stack, events...)
}

func SomeValueWithPath(anyValue any, path event.Path, stack Stack, events ...event.Event) Value {
	switch castValue := anyValue.(type) {
	case string:
		return SomeStringValueWithPath(castValue, path, stack, events...)

	case bool:
		return SomeBoolValueWithPath(castValue, path, stack, events...)

	case decimal.Decimal:
		return SomeDecimalValueWithPath(castValue, path, stack, events...)

	case int:
		return SomeDecimalValueWithPath(decimal.NewFromInt(int64(castValue)), path, stack, events...)

	case int8:
		return SomeDecimalValueWithPath(decimal.NewFromInt(int64(castValue)), path, stack, events...)

	case int16:
		return SomeDecimalValueWithPath(decimal.NewFromInt(int64(castValue)), path, stack, events...)

	case int32:
		return SomeDecimalValueWithPath(decimal.NewFromInt(int64(castValue)), path, stack, events...)

	case int64:
		return SomeDecimalValueWithPath(decimal.NewFromInt(castValue), path, stack, events...)

	case float32:
		return SomeDecimalValueWithPath(decimal.NewFromFloat32(castValue), path, stack, events...)

	case float64:
		return SomeDecimalValueWithPath(decimal.NewFromFloat(castValue), path, stack, events...)

	case []Value:
		return SomeArrayValueWithPath(castValue, path, stack, events...)

	case []any:
		array := make([]Value, 0)
		for _, item := range castValue {
			switch castItem := item.(type) {
			case Value:
				array = append(array, castItem)

			default:
				array = append(array, SomeValueWithPath(castItem, path, stack, events...))
			}
		}

		return SomeArrayValueWithPath(array, path, stack, events...)

	case *AnyValue:
		return &AnyValue{
			value:   castValue.Value(),
			path:    path,
			history: stack.History(append(castValue.History(), events...)...),
		}

	case *ArrayValue:
		return &ArrayValue{
			value:   castValue.ArrayValue(),
			path:    path,
			history: stack.History(append(castValue.History(), events...)...),
		}

	case *BoolValue:
		return &BoolValue{
			value:   castValue.BoolValue(),
			path:    path,
			history: stack.History(append(castValue.History(), events...)...),
		}

	case *DecimalValue:
		return &DecimalValue{
			value:   castValue.DecimalValue(),
			path:    path,
			history: stack.History(append(castValue.History(), events...)...),
		}

	case *StringValue:
		return &StringValue{
			value:   castValue.StringValue(),
			path:    path,
			history: stack.History(append(castValue.History(), events...)...),
		}
	}

	return &AnyValue{
		value:   anyValue,
		path:    path,
		history: stack.History(events...),
	}
}
