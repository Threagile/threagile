package expressions

import (
	"fmt"

	"github.com/threagile/threagile/pkg/risks/script/common"
)

type GreaterExpression struct {
	literal string
	first   common.ValueExpression
	second  common.ValueExpression
	as      string
}

func (what *GreaterExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	switch script.(type) {
	case map[string]any:
		for key, value := range script.(map[string]any) {
			switch key {
			case common.First:
				item, errorScript, itemError := new(ValueExpression).ParseValue(value)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse %q of equal-expression: %v", key, itemError)
				}

				what.first = item

			case common.Second:
				item, errorScript, itemError := new(ValueExpression).ParseValue(value)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse %q of equal-expression: %v", key, itemError)
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

func (what *GreaterExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *GreaterExpression) EvalBool(scope *common.Scope) (bool, string, error) {
	first, errorItemLiteral, itemError := what.first.EvalAny(scope)
	if itemError != nil {
		return false, errorItemLiteral, itemError
	}

	second, errorInLiteral, evalError := what.second.EvalAny(scope)
	if evalError != nil {
		return false, errorInLiteral, evalError
	}

	compareValue, compareError := common.Compare(first, second, what.as)
	if compareError != nil {
		return false, what.Literal(), fmt.Errorf("failed to eval equal-expression: %v", compareError)
	}

	return compareValue > 0, "", nil
}

func (what *GreaterExpression) EvalAny(scope *common.Scope) (any, string, error) {
	return what.EvalBool(scope)
}

func (what *GreaterExpression) Literal() string {
	return what.literal
}
