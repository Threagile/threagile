package common

import (
	"fmt"

	"github.com/threagile/threagile/pkg/risks/script/event"
)

type ArrayValue struct {
	value   []Value
	path    event.Path
	history event.History
}

func (what ArrayValue) PlainValue() any {
	values := make([]any, 0)
	for _, value := range what.value {
		values = append(values, value.PlainValue())
	}

	return values
}

func (what ArrayValue) Value() any {
	return what.value
}

func (what ArrayValue) Path() event.Path {
	return what.path
}

func (what ArrayValue) ValueText() event.Text {
	if len(what.value) == 0 {
		return new(event.Text).Append("(empty)")
	}

	text := make(event.Text, 0)
	for _, item := range what.value {
		itemText := item.Text()
		switch len(itemText) {
		case 0:
			text = new(event.Text).Append("  - (empty)")

		case 1:
			text = text.Append("  - " + itemText[0].Line)

		default:
			text = new(event.Text).Append("  - :", itemText...)
		}
	}

	return text
}

func (what ArrayValue) History() event.History {
	return what.history
}

func (what ArrayValue) Text() event.Text {
	if len(what.path) > 0 {
		return new(event.Text).Append(what.path.String())
	}

	return what.ValueText()
}

func (what ArrayValue) Description() event.Text {
	if len(what.path) == 0 {
		return what.History().Text()
	}

	if len(what.value) == 0 {
		return new(event.Text).Append(what.path.String() + " is (empty)")
	}

	return append(new(event.Text).Append(what.path.String()+" is:"), what.ValueText()...)
}

func (what ArrayValue) ArrayValue() []Value {
	return what.value
}

func EmptyArrayValue() *ArrayValue {
	return &ArrayValue{}
}

func SomeArrayValue(value []Value, stack Stack, events ...event.Event) *ArrayValue {
	return SomeArrayValueWithPath(value, nil, stack, events...)
}

func SomeArrayValueWithPath(value []Value, path event.Path, stack Stack, events ...event.Event) *ArrayValue {
	return &ArrayValue{
		value:   value,
		path:    path,
		history: stack.History(events...),
	}
}

func ToArrayValue(value Value) (*ArrayValue, error) {
	var arrayValue []Value
	switch castValue := value.Value().(type) {
	case []Value:
		arrayValue = castValue

	case []any:
		arrayValue = make([]Value, 0)
		for _, item := range castValue {
			arrayValue = append(arrayValue, SomeValue(item, nil))
		}

	default:
		return nil, fmt.Errorf("expected value-expression to eval to an array instead of %T", value.Value)
	}

	return &ArrayValue{
		value:   arrayValue,
		path:    value.Path(),
		history: value.History(),
	}, nil
}
