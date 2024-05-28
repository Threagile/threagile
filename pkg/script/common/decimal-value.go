package common

import (
	"fmt"
	"github.com/shopspring/decimal"
)

type DecimalValue struct {
	value   decimal.Decimal
	history History
}

func (what DecimalValue) Value() any {
	return what.value
}

func (what DecimalValue) History() History {
	return what.history
}

func (what DecimalValue) PlainValue() any {
	return what.value
}

func (what DecimalValue) DecimalValue() decimal.Decimal {
	return what.value
}

func EmptyDecimalValue() *DecimalValue {
	return &DecimalValue{
		value: decimal.Zero,
	}
}

func SomeDecimalValue(value decimal.Decimal, history History) *DecimalValue {
	if history == nil {
		history = NewHistory("")
	}

	return &DecimalValue{
		value:   value,
		history: history,
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
		history: value.History(),
	}, conversionError
}
