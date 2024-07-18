package common

import (
	"fmt"

	"github.com/threagile/threagile/pkg/risks/script/event"
)

func Compare(firstValue Value, secondValue Value, as string, stack Stack) (event.Event, error) {
	castFirstValue := firstValue
	castSecondValue := secondValue
	if len(as) > 0 {
		var castError error
		castFirstValue, castError = CastValue(firstValue, stack, as)
		if castError != nil {
			return nil, fmt.Errorf("failed to cast value to %q: %w", as, castError)
		}

		castSecondValue, castError = CastValue(secondValue, stack, as)
		if castError != nil {
			return nil, fmt.Errorf("failed to cast value to %q: %w", as, castError)
		}
	}

	return compare(castFirstValue, firstValue, castSecondValue, secondValue)
}

func compare(castFirstValue Value, origFirstValue Value, castSecondValue Value, origSecondValue Value) (event.Event, error) {
	switch first := castFirstValue.(type) {
	case *ArrayValue:
		second, conversionError := ToArrayValue(castSecondValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return compareArrays(first, origFirstValue, second, origSecondValue)

	case *BoolValue:
		second, conversionError := ToBoolValue(castSecondValue)
		if conversionError != nil {
			return nil, conversionError
		}

		if first.BoolValue() == second.BoolValue() {
			return event.NewEqual(origFirstValue, origSecondValue), nil
		}

		return event.NewNotEqual(origFirstValue, origSecondValue), nil

	case *DecimalValue:
		second, conversionError := ToDecimalValue(castSecondValue)
		if conversionError != nil {
			return nil, conversionError
		}

		value := first.DecimalValue().Cmp(second.DecimalValue())
		if value < 0 {
			return event.NewLess(origFirstValue, origSecondValue), nil
		} else if value > 0 {
			return event.NewGreater(origFirstValue, origSecondValue), nil
		}

		return event.NewEqual(origFirstValue, origSecondValue), nil

	case *StringValue:
		second, conversionError := ToStringValue(castSecondValue)
		if conversionError != nil {
			return nil, conversionError
		}

		if first.StringValue() == second.StringValue() {
			return event.NewEqual(origFirstValue, origSecondValue), nil
		}

		return event.NewNotEqual(origFirstValue, origSecondValue), nil

	case *AnyValue:
		if castFirstValue.Value() == nil {
			return compare(nil, origFirstValue, castSecondValue, origSecondValue)
		}

	case nil:
		switch second := castSecondValue.(type) {
		case *ArrayValue:
			if len(second.ArrayValue()) == 0 {
				return event.NewEqual(origFirstValue, origSecondValue), nil
			}

			return event.NewNotEqual(origFirstValue, origSecondValue), nil

		case *BoolValue:
			if !second.BoolValue() {
				return event.NewEqual(origFirstValue, origSecondValue), nil
			}

			return event.NewNotEqual(origFirstValue, origSecondValue), nil

		case *DecimalValue:
			if second.DecimalValue().IsZero() {
				return event.NewEqual(origFirstValue, origSecondValue), nil
			}

			return event.NewNotEqual(origFirstValue, origSecondValue), nil

		case *StringValue:
			if len(second.StringValue()) == 0 {
				return event.NewEqual(origFirstValue, origSecondValue), nil
			}

			return event.NewNotEqual(origFirstValue, origSecondValue), nil

		case *AnyValue:
			if second.Value() == nil {
				return event.NewEqual(origFirstValue, origSecondValue), nil
			}

		case nil:
			return event.NewEqual(origFirstValue, origSecondValue), nil
		}
	}

	return nil, fmt.Errorf("can't compare %T to %T", origFirstValue, origSecondValue)
}

func compareArrays(firstValue *ArrayValue, origFirstValue Value, secondValue *ArrayValue, origSecondValue Value) (event.Event, error) {
	if len(firstValue.ArrayValue()) != len(secondValue.ArrayValue()) {
		return event.NewNotEqual(origFirstValue, origSecondValue), nil
	}

	for index, first := range firstValue.ArrayValue() {
		second := secondValue.ArrayValue()[index]
		result, compareError := compare(first, first, second, second)
		if compareError != nil {
			return result, compareError
		}

		if !IsSame(result) {
			return event.NewNotEqual(origFirstValue, origSecondValue), nil
		}
	}

	return event.NewEqual(origFirstValue, origSecondValue), nil
}

func IsSame(e event.Event) bool {
	if e == nil {
		return false
	}

	switch e.(type) {
	case *event.Equal:
		return true
	}

	return false
}

func IsGreater(e event.Event) bool {
	if e == nil {
		return false
	}

	switch e.(type) {
	case *event.Greater:
		return true
	}

	return false
}

func IsLess(e event.Event) bool {
	if e == nil {
		return false
	}

	switch e.(type) {
	case *event.Less:
		return true
	}

	return false
}
