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
					return nil, errorScript, fmt.Errorf("failed to parse %q of contains-expression: %w", key, itemError)
				}

				what.item = item

			case common.In:
				item, errorScript, itemError := new(ValueExpression).ParseValue(value)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse %q of contains-expression: %w", key, itemError)
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

func (what *ContainsExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	item, errorItemLiteral, itemError := what.item.EvalAny(scope)
	if itemError != nil {
		return common.EmptyBoolValue(), errorItemLiteral, itemError
	}

	inValue, errorInLiteral, evalError := what.in.EvalAny(scope)
	if evalError != nil {
		return common.EmptyBoolValue(), errorInLiteral, evalError
	}

	return what.evalBool(scope, item, inValue)
}

func (what *ContainsExpression) evalBool(scope *common.Scope, item common.Value, inValue common.Value) (*common.BoolValue, string, error) {
	switch castValue := inValue.Value().(type) {
	case []any:
		for index, value := range castValue {
			compareValue, compareError := common.Compare(item, common.SomeValue(value, nil), what.as)
			if compareError != nil {
				return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to eval contains-expression: can't compare value to item #%v: %w", index+1, compareError)
			}

			if common.IsSame(compareValue.Property) {
				return common.SomeBoolValue(true, compareValue), "", nil
			}
		}

		return common.SomeBoolValue(false, nil), "", nil

	case []common.Value:
		for index, value := range castValue {
			compareValue, compareError := common.Compare(item, common.SomeValue(value.Value(), value.Event()), what.as)
			if compareError != nil {
				return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to eval contains-expression: can't compare value to item #%v: %w", index+1, compareError)
			}

			if common.IsSame(compareValue.Property) {
				return common.SomeBoolValue(true, compareValue), "", nil
			}
		}

		return common.SomeBoolValue(false, nil), "", nil

	case map[string]any:
		for name, value := range castValue {
			compareValue, compareError := common.Compare(item, common.SomeValue(value, nil), what.as)
			if compareError != nil {
				return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to eval contains-expression: can't compare value to item %q: %w", name, compareError)
			}

			if common.IsSame(compareValue.Property) {
				return common.SomeBoolValue(true, compareValue), "", nil
			}
		}

		return common.SomeBoolValue(false, nil), "", nil

	case common.Value:
		return what.evalBool(scope, item, common.SomeValue(castValue.Value(), inValue.Event()))

	case nil:
		return common.SomeBoolValue(false, nil), "", nil

	default:
		return common.EmptyBoolValue(), "", fmt.Errorf("failed to eval contains-expression: expected iterable type, got %T", inValue)
	}
}

func (what *ContainsExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *ContainsExpression) Literal() string {
	return what.literal
}
