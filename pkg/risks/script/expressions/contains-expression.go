package expressions

import (
	"fmt"

	"github.com/threagile/threagile/pkg/risks/script/common"
)

type ContainsExpression struct {
	literal string
	item    common.ValueExpression
	in      common.ValueExpression
	as      string
}

func (what *ContainsExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	switch script.(type) {
	case map[string]any:
		for key, value := range script.(map[string]any) {
			switch key {
			case common.Item:
				item, errorScript, itemError := new(ValueExpression).ParseValue(value)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse %q of contains-expression: %v", key, itemError)
				}

				what.item = item

			case common.In:
				item, errorScript, itemError := new(ValueExpression).ParseValue(value)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse %q of contains-expression: %v", key, itemError)
				}

				what.in = item

			case common.As:
				item, ok := value.(string)
				if !ok {
					return nil, script, fmt.Errorf("failed to parse contains-expression: %q is not a string but %T", key, value)
				}

				what.as = item

			default:
				return nil, script, fmt.Errorf("failed to parse contains-expression: unexpected keyword %q", key)
			}
		}

	default:
		return nil, script, fmt.Errorf("failed to parse contains-expression: expected map[string]any, got %T", script)
	}

	return what, nil, nil
}

func (what *ContainsExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *ContainsExpression) EvalBool(scope *common.Scope) (bool, string, error) {
	item, errorItemLiteral, itemError := what.item.EvalAny(scope)
	if itemError != nil {
		return false, errorItemLiteral, itemError
	}

	in, errorInLiteral, evalError := what.in.EvalAny(scope)
	if evalError != nil {
		return false, errorInLiteral, evalError
	}

	switch castIn := in.(type) {
	case []any:
		for index, value := range castIn {
			compareValue, compareError := common.Compare(item, value, what.as)
			if compareError != nil {
				return false, what.Literal(), fmt.Errorf("failed to eval contains-expression: can't compare value to item #%d: %v", index+1, compareError)
			}

			if compareValue == 0 {
				return true, "", nil
			}
		}

		return false, "", nil

	case map[string]any:
		for name, value := range castIn {
			compareValue, compareError := common.Compare(item, value, what.as)
			if compareError != nil {
				return false, what.Literal(), fmt.Errorf("failed to eval contains-expression: can't compare value to item %q: %v", name, compareError)
			}

			if compareValue == 0 {
				return true, "", nil
			}
		}

		return false, "", nil

	default:
		return false, "", fmt.Errorf("failed to eval contains-expression: expected iterable type, got %T", in)
	}
}

func (what *ContainsExpression) EvalAny(scope *common.Scope) (any, string, error) {
	return what.EvalBool(scope)
}

func (what *ContainsExpression) Literal() string {
	return what.literal
}
