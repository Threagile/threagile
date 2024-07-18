package common

import (
	"fmt"

	"github.com/threagile/threagile/pkg/risks/script/event"
)

type StringValue struct {
	value   string
	path    event.Path
	history event.History
}

func (what StringValue) PlainValue() any {
	return what.value
}

func (what StringValue) Value() any {
	return what.value
}

func (what StringValue) Path() event.Path {
	return what.path
}

func (what StringValue) ValueText() event.Text {
	text := make(event.Text, 0)
	for _, item := range event.GetLines(what.value) {
		text = text.Append(item)
	}

	return text
}

func (what StringValue) History() event.History {
	return what.history
}

func (what StringValue) Text() event.Text {
	if len(what.path) > 0 {
		return new(event.Text).Append(what.path.String())
	}

	return what.ValueText()
}

func (what StringValue) Description() event.Text {
	if len(what.path) == 0 {
		return what.History().Text()
	}

	if len(what.value) == 0 {
		return new(event.Text).Append(what.path.String() + " is (empty)")
	}

	lines := event.GetLines(what.value)
	if len(lines) == 1 {
		return new(event.Text).Append(fmt.Sprintf("%v is %q", what.path.String(), lines[0]))
	}

	return append(new(event.Text).Append(what.path.String()+" is:"), what.ValueText()...)
}

func (what StringValue) StringValue() string {
	return what.value
}

func EmptyStringValue() *StringValue {
	return &StringValue{}
}

func SomeStringValue(value string, stack Stack, events ...event.Event) *StringValue {
	return SomeStringValueWithPath(value, nil, stack, events...)
}

func SomeStringValueWithPath(value string, path event.Path, stack Stack, events ...event.Event) *StringValue {
	return &StringValue{
		value:   value,
		path:    path,
		history: stack.History(events...),
	}
}

func ToStringValue(value Value) (*StringValue, error) {
	castValue, ok := value.Value().(string)

	var conversionError error
	if !ok {
		conversionError = fmt.Errorf("expected value-expression to eval to a string instead of %T", value.Value)
	}

	return &StringValue{
		value:   castValue,
		path:    value.Path(),
		history: value.History(),
	}, conversionError
}
