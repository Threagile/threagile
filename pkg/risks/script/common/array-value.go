package common

import (
	"fmt"
)

type ArrayValue struct {
	value []Value
	name  Path
	event *Event
}

func (what ArrayValue) Value() any {
	return what.value
}

func (what ArrayValue) Name() Path {
	return what.name
}

func (what ArrayValue) SetName(name ...string) {
	what.name.SetPath(name...)
}

func (what ArrayValue) Event() *Event {
	return what.event
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

func (what ArrayValue) Text() []string {
	text := make([]string, 0)
	for _, item := range what.value {
		itemText := item.Text()
		switch len(itemText) {
		case 0:

		case 1:
			text = append(text, "  - "+itemText[0])

		default:
			text = append(text, "  - ")

			for _, line := range itemText {
				text = append(text, "      "+line)
			}
		}
	}

	return text
}

func EmptyArrayValue() *ArrayValue {
	return &ArrayValue{}
}

func SomeArrayValue(value []Value, event *Event) *ArrayValue {
	return &ArrayValue{
		value: value,
		event: event,
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
		value: arrayValue,
		name:  value.Name(),
		event: value.Event(),
	}, nil
}
