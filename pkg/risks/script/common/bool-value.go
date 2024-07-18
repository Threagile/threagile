package common

import (
	"fmt"

	"github.com/threagile/threagile/pkg/risks/script/event"
)

type BoolValue struct {
	value   bool
	path    event.Path
	history event.History
}

func (what BoolValue) PlainValue() any {
	return what.value
}

func (what BoolValue) Value() any {
	return what.value
}

func (what BoolValue) Path() event.Path {
	return what.path
}

func (what BoolValue) ValueText() event.Text {
	return new(event.Text).Append(fmt.Sprintf("%v", what.value))
}

func (what BoolValue) History() event.History {
	return what.history
}

func (what BoolValue) Text() event.Text {
	if len(what.path) > 0 {
		return new(event.Text).Append(what.path.String())
	}

	return what.ValueText()
}

func (what BoolValue) Description() event.Text {
	if len(what.path) == 0 {
		return what.History().Text()
	}

	return new(event.Text).Append(fmt.Sprintf("%v is %v", what.path.String(), what.value))
}

func (what BoolValue) BoolValue() bool {
	return what.value
}

func EmptyBoolValue() *BoolValue {
	return &BoolValue{}
}

func SomeBoolValue(value bool, stack Stack, events ...event.Event) *BoolValue {
	return SomeBoolValueWithPath(value, nil, stack, events...)
}

func SomeBoolValueWithPath(value bool, path event.Path, stack Stack, events ...event.Event) *BoolValue {
	return &BoolValue{
		value:   value,
		path:    path,
		history: stack.History(events...),
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
		path:    value.Path(),
		history: value.History(),
	}, conversionError
}
