package common

import (
	"fmt"

	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/risks/script/event"
)

type DecimalValue struct {
	value   decimal.Decimal
	path    event.Path
	history event.History
}

func (what DecimalValue) PlainValue() any {
	return what.value
}

func (what DecimalValue) Value() any {
	return what.value
}

func (what DecimalValue) Path() event.Path {
	return what.path
}

func (what DecimalValue) ValueText() event.Text {
	return new(event.Text).Append(what.value.String())
}

func (what DecimalValue) History() event.History {
	return what.history
}

func (what DecimalValue) Text() event.Text {
	if len(what.path) > 0 {
		return new(event.Text).Append(what.path.String())
	}

	return what.ValueText()
}

func (what DecimalValue) Description() event.Text {
	if len(what.path) == 0 {
		return what.History().Text()
	}

	return new(event.Text).Append(fmt.Sprintf("%v is %v", what.path.String(), what.value.String()))
}

func (what DecimalValue) DecimalValue() decimal.Decimal {
	return what.value
}

func EmptyDecimalValue() *DecimalValue {
	return &DecimalValue{
		value: decimal.Zero,
	}
}

func SomeDecimalValue(value decimal.Decimal, stack Stack, events ...event.Event) *DecimalValue {
	return SomeDecimalValueWithPath(value, nil, stack, events...)
}

func SomeDecimalValueWithPath(value decimal.Decimal, path event.Path, stack Stack, events ...event.Event) *DecimalValue {
	return &DecimalValue{
		value:   value,
		path:    path,
		history: stack.History(events...),
	}
}

func ToDecimalValue(value Value) (*DecimalValue, error) {
	castValue, ok := value.Value().(decimal.Decimal)

	var conversionError error
	if !ok {
		conversionError = fmt.Errorf("expected value-expression to eval to a decimal instead of %T", value.Value)
	}

	return &DecimalValue{
		value:   castValue,
		path:    value.Path(),
		history: value.History(),
	}, conversionError
}
