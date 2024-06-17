package common

import (
	"fmt"
	"github.com/threagile/threagile/pkg/risks/script/property"
)

func Compare(first Value, second Value, as string) (*Event, error) {
	firstValue := first
	secondValue := second
	if len(as) > 0 {
		var castError error
		firstValue, castError = CastValue(firstValue, as)
		if castError != nil {
			return nil, fmt.Errorf("failed to cast value to %q: %w", as, castError)
		}

		secondValue, castError = CastValue(secondValue, as)
		if castError != nil {
			return nil, fmt.Errorf("failed to cast value to %q: %w", as, castError)
		}
	}

	return compare(firstValue, secondValue)
}

func compare(firstValue Value, secondValue Value) (*Event, error) {
	switch first := firstValue.(type) {
	case *ArrayValue:
		second, conversionError := ToArrayValue(secondValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return compareArrays(first, second)

	case *BoolValue:
		second, conversionError := ToBoolValue(secondValue)
		if conversionError != nil {
			return nil, conversionError
		}

		if first.BoolValue() == second.BoolValue() {
			return NewEventFrom(NewEqualProperty(second), first, second), nil
		}

		return NewEventFrom(NewNotEqualProperty(second), first, second), nil

	case *DecimalValue:
		second, conversionError := ToDecimalValue(secondValue)
		if conversionError != nil {
			return nil, conversionError
		}

		value := first.DecimalValue().Cmp(second.DecimalValue())
		prop := NewEqualProperty(secondValue)
		if value < 0 {
			prop = NewLessProperty(secondValue)
		} else if value > 0 {
			prop = NewGreaterProperty(secondValue)
		}

		return NewEventFrom(prop, first, second), nil

	case *StringValue:
		second, conversionError := ToStringValue(secondValue)
		if conversionError != nil {
			return nil, conversionError
		}

		if first.StringValue() == second.StringValue() {
			return NewEventFrom(NewEqualProperty(second), first, second), nil
		}

		return NewEventFrom(NewNotEqualProperty(second), first, second), nil

	case *AnyValue:
		if firstValue.Value() == nil {
			return compare(nil, secondValue)
		}

	case nil:
		switch second := secondValue.(type) {
		case *ArrayValue:
			if len(second.ArrayValue()) == 0 {
				return NewEventFrom(NewEqualProperty(second), first, second), nil
			}

			return NewEventFrom(NewNotEqualProperty(second), first, second), nil

		case *BoolValue:
			if second.BoolValue() == false {
				return NewEventFrom(NewEqualProperty(second), first, second), nil
			}

			return NewEventFrom(NewNotEqualProperty(second), first, second), nil

		case *DecimalValue:
			if second.DecimalValue().IsZero() {
				return NewEventFrom(NewEqualProperty(second), first, second), nil
			}

			return NewEventFrom(NewNotEqualProperty(second), first, second), nil

		case *StringValue:
			if len(second.StringValue()) == 0 {
				return NewEventFrom(NewEqualProperty(second), first, second), nil
			}

			return NewEventFrom(NewNotEqualProperty(second), first, second), nil

		case *AnyValue:
			if second.Value() == nil {
				return NewEvent(NewEqualProperty(nil), nil), nil
			}

		case nil:
			return NewEvent(NewEqualProperty(nil), nil), nil
		}
	}

	return nil, fmt.Errorf("can't compare %T to %T", firstValue, secondValue)
}

func compareArrays(firstValue *ArrayValue, secondValue *ArrayValue) (*Event, error) {
	if len(firstValue.ArrayValue()) != len(secondValue.ArrayValue()) {
		return NewEventFrom(NewNotEqualProperty(firstValue), firstValue, secondValue), nil
	}

	for index, first := range firstValue.ArrayValue() {
		second := secondValue.ArrayValue()[index]
		event, compareError := compare(first, second)
		if compareError != nil {
			return event, compareError
		}

		if !IsSame(event.Property) {
			return NewEventFrom(NewNotEqualProperty(firstValue), firstValue, secondValue), nil
		}
	}

	return NewEventFrom(NewEqualProperty(firstValue), firstValue, secondValue), nil
}

func IsSame(value *Property) bool {
	if value == nil {
		return false
	}

	switch value.Property.(type) {
	case *property.Equal:
		return true
	}

	return false
}

func IsGreater(value *Property) bool {
	if value == nil {
		return false
	}

	switch value.Property.(type) {
	case *property.Greater:
		return true
	}

	return false
}

func IsLess(value *Property) bool {
	if value == nil {
		return false
	}

	switch value.Property.(type) {
	case *property.Less:
		return true
	}

	return false
}

func ToString(value any) (*StringValue, error) {
	switch castValue := value.(type) {
	case string:
		return SomeStringValue(castValue, nil), nil

	case *StringValue:
		return castValue, nil

	case *AnyValue:
		aString, valueError := ToString(castValue.Value())
		stringValue := SomeStringValue(aString.StringValue(), castValue.Event())
		if valueError != nil {
			return stringValue, valueError
		}

		return stringValue, nil

	default:
		return EmptyStringValue(), fmt.Errorf("expected string, got %T", value)
	}
}
