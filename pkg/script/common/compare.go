package common

import (
	"fmt"
	"github.com/shopspring/decimal"
	"strings"
)

func Compare(first Value, second Value, as string) (*DecimalValue, error) {
	firstValue := first
	secondValue := second
	if len(as) > 0 {
		var castError error
		firstValue, castError = CastValue(firstValue, as)
		if castError != nil {
			return EmptyDecimalValue(), fmt.Errorf("failed to cast value to %q: %w", as, castError)
		}

		secondValue, castError = CastValue(secondValue, as)
		if castError != nil {
			return EmptyDecimalValue(), fmt.Errorf("failed to cast value to %q: %w", as, castError)
		}
	}

	compatibilityError := checkComparability(firstValue, secondValue)
	if compatibilityError != nil {
		return EmptyDecimalValue(), compatibilityError
	}

	if isString(firstValue) {
		if !isString(secondValue) {
			return EmptyDecimalValue(), fmt.Errorf("can't compare string to %T", secondValue)
		}

		return compareStrings(firstValue, secondValue)
	}

	firstDecimal, firstDecimalError := toDecimal(firstValue)
	if firstDecimalError != nil {
		return EmptyDecimalValue(), firstDecimalError
	}

	secondDecimal, secondDecimalError := toDecimal(secondValue)
	if secondDecimalError != nil {
		return EmptyDecimalValue(), secondDecimalError
	}

	return SomeDecimalValue(decimal.NewFromInt(int64(firstDecimal.DecimalValue().Cmp(secondDecimal.DecimalValue()))), NewHistory("comparing values").From(firstDecimal.History(), secondDecimal.History())), nil
}

func IsSame(value *DecimalValue) bool {
	return value.DecimalValue().IsZero()
}

func IsGreater(value *DecimalValue) bool {
	return value.DecimalValue().IsPositive()
}

func IsLess(value *DecimalValue) bool {
	return value.DecimalValue().IsNegative()
}

func checkComparability(firstValue any, secondValue any) error {
	switch castFirstValue := firstValue.(type) {
	case BoolValue, *BoolValue, bool:
		switch castSecondValue := secondValue.(type) {
		case BoolValue, *BoolValue, bool:
			return nil

		case AnyValue:
			return checkComparability(firstValue, castSecondValue.Value())

		case *AnyValue:
			return checkComparability(firstValue, castSecondValue.Value())
		}

	case DecimalValue, *DecimalValue, decimal.Decimal, int, int64, float64:
		switch castSecondValue := secondValue.(type) {
		case DecimalValue, *DecimalValue, decimal.Decimal, int, int64, float64:
			return nil

		case AnyValue:
			return checkComparability(firstValue, castSecondValue.Value())

		case *AnyValue:
			return checkComparability(firstValue, castSecondValue.Value())
		}

	case StringValue, *StringValue, string, fmt.Stringer:
		switch castSecondValue := secondValue.(type) {
		case StringValue, *StringValue, string, fmt.Stringer:
			return nil

		case AnyValue:
			return checkComparability(firstValue, castSecondValue.Value())

		case *AnyValue:
			return checkComparability(firstValue, castSecondValue.Value())
		}

	case AnyValue:
		return checkComparability(castFirstValue.Value(), secondValue)

	case *AnyValue:
		return checkComparability(castFirstValue.Value(), secondValue)

	case nil:
		return nil
	}

	return fmt.Errorf("can't compare %T to %T", firstValue, secondValue)
}

func ToString(value any) (*StringValue, error) {
	switch castValue := value.(type) {
	case string:
		return SomeStringValue(castValue, NewHistory("")), nil

	case fmt.Stringer:
		return SomeStringValue(castValue.String(), NewHistory("")), nil

	case StringValue:
		return &castValue, nil

	case *StringValue:
		return castValue, nil

	case AnyValue:
		aString, valueError := ToString(castValue.Value())
		stringValue := SomeStringValue(aString.StringValue(), castValue.History())
		if valueError != nil {
			return stringValue, valueError
		}

		return stringValue, nil

	case *AnyValue:
		aString, valueError := ToString(castValue.Value())
		stringValue := SomeStringValue(aString.StringValue(), castValue.History())
		if valueError != nil {
			return stringValue, valueError
		}

		return stringValue, nil

	default:
		return EmptyStringValue(), fmt.Errorf("expected string, got %T", value)
	}
}

func toDecimal(value any) (*DecimalValue, error) {
	switch castValue := value.(type) {
	case BoolValue:
		if castValue.BoolValue() {
			return SomeDecimalValue(decimal.NewFromInt(1), NewHistory("is true").From(castValue.History())), nil
		} else {
			return SomeDecimalValue(decimal.NewFromInt(0), NewHistory("is false").From(castValue.History())), nil
		}

	case *BoolValue:
		if castValue.BoolValue() {
			return SomeDecimalValue(decimal.NewFromInt(1), NewHistory("is true").From(castValue.History())), nil
		} else {
			return SomeDecimalValue(decimal.NewFromInt(0), NewHistory("is false").From(castValue.History())), nil
		}

	case bool:
		if castValue {
			return SomeDecimalValue(decimal.NewFromInt(1), NewHistory("is true")), nil
		} else {
			return SomeDecimalValue(decimal.NewFromInt(0), NewHistory("is false")), nil
		}

	case DecimalValue:
		return &castValue, nil

	case *DecimalValue:
		return castValue, nil

	case decimal.Decimal:
		return SomeDecimalValue(castValue, NewHistory("is %v", castValue)), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), NewHistory("is %v", castValue)), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), NewHistory("is %v", castValue)), nil

	case float64:
		return SomeDecimalValue(decimal.NewFromFloat(castValue), NewHistory("is %v", castValue)), nil

	case AnyValue:
		return toDecimal(castValue.Value())

	case *AnyValue:
		return toDecimal(castValue.Value())

	case nil:
		return EmptyDecimalValue(), nil

	default:
		return EmptyDecimalValue(), fmt.Errorf("can't compare values of type %T", value)
	}
}

func isString(value any) bool {
	switch castValue := value.(type) {
	case string, fmt.Stringer, StringValue, *StringValue:
		return true

	case AnyValue:
		return isString(castValue.Value())

	case *AnyValue:
		return isString(castValue.Value())

	default:
		return false
	}
}

func compareStrings(firstValue any, secondValue any) (*DecimalValue, error) {
	firstStringValue, firstStringError := ToString(firstValue)
	if firstStringError != nil {
		return EmptyDecimalValue(), fmt.Errorf("error for first value: %w", firstStringError)
	}

	secondStringValue, secondStringError := ToString(secondValue)
	if secondStringError != nil {
		return EmptyDecimalValue(), fmt.Errorf("error for second value: %w", secondStringError)
	}

	return SomeDecimalValue(decimal.NewFromInt(int64(strings.Compare(firstStringValue.StringValue(), secondStringValue.StringValue()))), NewHistory("comparing values").From(firstStringValue.History(), secondStringValue.History())), nil
}
