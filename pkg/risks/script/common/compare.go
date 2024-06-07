package common

import (
	"fmt"
	"strings"

	"github.com/shopspring/decimal"
)

func Compare(first any, second any, as string) (int, error) {
	firstValue := first
	secondValue := second
	if len(as) > 0 {
		var castError error
		firstValue, castError = CastValue(firstValue, as)
		if castError != nil {
			return 0, fmt.Errorf("failed to cast value: %v", castError)
		}

		secondValue, castError = CastValue(secondValue, as)
		if castError != nil {
			return 0, fmt.Errorf("failed to cast value: %v", castError)
		}
	}

	var firstDecimal decimal.Decimal
	switch castValue := firstValue.(type) {
	case bool:
		secondBool, ok := secondValue.(bool)
		if !ok {
			return 0, fmt.Errorf("can't compare bool to %T", secondValue)
		}

		if firstValue.(bool) {
			if secondBool {
				return 0, nil
			} else {
				return 1, nil
			}
		} else {
			if secondBool {
				return -1, nil
			} else {
				return 0, nil
			}
		}

	case decimal.Decimal:
		firstDecimal = castValue

	case int:
		firstDecimal = decimal.NewFromInt(int64(castValue))

	case int64:
		firstDecimal = decimal.NewFromInt(castValue)

	case float64:
		firstDecimal = decimal.NewFromFloat(castValue)

	case string, fmt.Stringer:
		firstString := ""
		switch castFirstValue := firstValue.(type) {
		case string:
			firstString = castFirstValue

		case fmt.Stringer:
			firstString = castFirstValue.String()
		}

		secondString := ""
		switch castSecondValue := secondValue.(type) {
		case string:
			secondString = castSecondValue

		case fmt.Stringer:
			secondString = castSecondValue.String()

		default:
			return 0, fmt.Errorf("can't compare string to %T", secondValue)
		}

		return strings.Compare(firstString, secondString), nil

	default:
		return 0, fmt.Errorf("can't compare %T to %T", firstValue, secondValue)
	}

	var secondDecimal decimal.Decimal
	switch castSecondValue := secondValue.(type) {
	case decimal.Decimal:
		secondDecimal = castSecondValue

	case int:
		secondDecimal = decimal.NewFromInt(int64(castSecondValue))

	case int64:
		secondDecimal = decimal.NewFromInt(castSecondValue)

	case float64:
		secondDecimal = decimal.NewFromFloat(castSecondValue)

	default:
		return 0, fmt.Errorf("can't compare decimal to %T", secondValue)
	}

	return firstDecimal.Cmp(secondDecimal), nil
}
