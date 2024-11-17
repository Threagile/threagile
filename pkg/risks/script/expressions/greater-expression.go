package expressions

import (
	"fmt"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

type GreaterExpression struct {
	literal string
	first   common.ValueExpression
	second  common.ValueExpression
	as      common.StringExpression
}

func (what *GreaterExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	switch castScript := script.(type) {
	case map[string]any:
		for key, value := range castScript {
			switch key {
			case common.First:
				item, errorScript, itemError := new(ValueExpression).ParseValue(value)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse %q of equal-expression: %w", key, itemError)
				}

				what.first = item

			case common.Second:
				item, errorScript, itemError := new(ValueExpression).ParseValue(value)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse %q of equal-expression: %w", key, itemError)
				}

				what.second = item

			case common.As:
				item, errorScript, itemError := new(ValueExpression).ParseValue(value)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse %q of equal-expression: %w", key, itemError)
				}

				what.as = item

			default:
				return nil, script, fmt.Errorf("failed to parse equal-expression: unexpected keyword %q", key)
			}
		}

	default:
		return nil, script, fmt.Errorf("failed to parse equal-expression: expected map[string]any, got %T", script)
	}

	return what, nil, nil
}

func (what *GreaterExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *GreaterExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	first, errorItemLiteral, itemError := what.first.EvalAny(scope)
	if itemError != nil {
		return common.EmptyBoolValue(), errorItemLiteral, itemError
	}

	second, errorInLiteral, evalError := what.second.EvalAny(scope)
	if evalError != nil {
		return common.EmptyBoolValue(), errorInLiteral, evalError
	}

	as, errorAsLiteral, asError := what.as.EvalString(scope)
	if asError != nil {
		return common.EmptyBoolValue(), errorAsLiteral, asError
	}

	compareValue, compareError := common.Compare(first, second, as.StringValue())
	if compareError != nil {
		return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to compare equal-expression: %w", compareError)
	}

	if common.IsGreater(compareValue.Property) {
		return common.SomeBoolValue(true, compareValue), "", nil
	}

	return common.SomeBoolValue(false, compareValue), "", nil
}

func (what *GreaterExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *GreaterExpression) Literal() string {
	return what.literal
}
