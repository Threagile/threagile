package expressions

import (
	"fmt"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

type NotEqualExpression struct {
	literal string
	first   common.ValueExpression
	second  common.ValueExpression
	as      string
}

func (what *NotEqualExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	switch script.(type) {
	case map[string]any:
		for key, value := range script.(map[string]any) {
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
				item, ok := value.(string)
				if !ok {
					return nil, script, fmt.Errorf("failed to parse equal-expression: %q is not a string but %T", key, value)
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

func (what *NotEqualExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *NotEqualExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	first, errorItemLiteral, itemError := what.first.EvalAny(scope)
	if itemError != nil {
		return common.EmptyBoolValue(), errorItemLiteral, itemError
	}

	second, errorInLiteral, evalError := what.second.EvalAny(scope)
	if evalError != nil {
		return common.EmptyBoolValue(), errorInLiteral, evalError
	}

	compareValue, compareError := common.Compare(first, second, what.as)
	if compareError != nil {
		return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to compare not-equal-expression: %w", compareError)
	}

	if !common.IsSame(compareValue.Property) {
		return common.SomeBoolValue(true, compareValue), "", nil
	}

	return common.SomeBoolValue(false, compareValue), "", nil
}

func (what *NotEqualExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *NotEqualExpression) Literal() string {
	return what.literal
}
