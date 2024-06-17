package common

import (
	"fmt"
	"github.com/shopspring/decimal"
)

type DecimalValue struct {
	value decimal.Decimal
	name  Path
	event *Event
}

func (what DecimalValue) Value() any {
	return what.value
}

func (what DecimalValue) Name() Path {
	return what.name
}

func (what DecimalValue) SetName(name ...string) {
	what.name.SetPath(name...)
}

func (what DecimalValue) Event() *Event {
	return what.event
}

func (what DecimalValue) PlainValue() any {
	return what.value
}

func (what DecimalValue) Text() []string {
	return []string{what.value.String()}
}

func (what DecimalValue) DecimalValue() decimal.Decimal {
	return what.value
}

func EmptyDecimalValue() *DecimalValue {
	return &DecimalValue{
		value: decimal.Zero,
	}
}

func SomeDecimalValue(value decimal.Decimal, event *Event) *DecimalValue {
	return &DecimalValue{
		value: value,
		event: event,
	}
}

func ToDecimalValue(value Value) (*DecimalValue, error) {
	castValue, ok := value.Value().(decimal.Decimal)

	var conversionError error
	if !ok {
		conversionError = fmt.Errorf("expected value-expression to eval to a decimal instead of %T", value.Value)
	}

	return &DecimalValue{
		value: castValue,
		name:  value.Name(),
		event: value.Event(),
	}, conversionError
}
