package common

import (
	"fmt"
)

type BoolValue struct {
	value bool
	name  Path
	event *Event
}

func (what BoolValue) Value() any {
	return what.value
}

func (what BoolValue) Name() Path {
	return what.name
}

func (what BoolValue) SetName(name ...string) {
	what.name.SetPath(name...)
}

func (what BoolValue) Event() *Event {
	return what.event
}

func (what BoolValue) PlainValue() any {
	return what.value
}

func (what BoolValue) Text() []string {
	return []string{fmt.Sprintf("%v", what.value)}
}

func (what BoolValue) BoolValue() bool {
	return what.value
}

func EmptyBoolValue() *BoolValue {
	return &BoolValue{}
}

func SomeBoolValue(value bool, event *Event) *BoolValue {
	return &BoolValue{
		value: value,
		event: event,
	}
}

func ToBoolValue(value Value) (*BoolValue, error) {
	castValue, ok := value.Value().(bool)

	var conversionError error
	if !ok {
		conversionError = fmt.Errorf("expected value-expression to eval to a bool instead of %T", value.Value)
	}

	return &BoolValue{
		value: castValue,
		name:  value.Name(),
		event: value.Event(),
	}, conversionError
}
