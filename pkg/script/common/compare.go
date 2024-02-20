package common

import (
	"fmt"
	"github.com/shopspring/decimal"
	"strings"
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

	firstDecimal := decimal.NewFromInt(0)
	switch firstValue.(type) {
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
		firstDecimal = firstValue.(decimal.Decimal)

	case int:
		firstDecimal = decimal.NewFromInt(int64(firstValue.(int)))

	case int64:
		firstDecimal = decimal.NewFromInt(firstValue.(int64))

	case float64:
		firstDecimal = decimal.NewFromFloat(firstValue.(float64))

	case string, fmt.Stringer:
		firstString := ""
		switch firstValue.(type) {
		case string:
			firstString = firstValue.(string)

		case fmt.Stringer:
			firstString = firstValue.(fmt.Stringer).String()
		}

		secondString := ""
		switch secondValue.(type) {
		case string:
			secondString = secondValue.(string)

		case fmt.Stringer:
			secondString = secondValue.(fmt.Stringer).String()

		default:
			return 0, fmt.Errorf("can't compare string to %T", secondValue)
		}

		return strings.Compare(firstString, secondString), nil

	default:
		return 0, fmt.Errorf("can't compare %T to %T", firstValue, secondValue)
	}

	secondDecimal := decimal.NewFromInt(0)
	switch secondValue.(type) {
	case decimal.Decimal:
		secondDecimal = secondValue.(decimal.Decimal)

	case int:
		secondDecimal = decimal.NewFromInt(int64(secondValue.(int)))

	case int64:
		secondDecimal = decimal.NewFromInt(secondValue.(int64))

	case float64:
		secondDecimal = decimal.NewFromFloat(secondValue.(float64))

	default:
		return 0, fmt.Errorf("can't compare decimal to %T", secondValue)
	}

	return firstDecimal.Cmp(secondDecimal), nil
}
