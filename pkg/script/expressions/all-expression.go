package expressions

import (
	"fmt"
	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/script/common"
)

type AllExpression struct {
	literal    string
	in         common.ValueExpression
	item       string
	index      string
	expression common.BoolExpression
}

func (what *AllExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	switch script.(type) {
	case map[string]any:
		for key, value := range script.(map[string]any) {
			switch key {
			case common.In:
				item, errorExpression, itemError := new(ValueExpression).ParseValue(value)
				if itemError != nil {
					return nil, errorExpression, fmt.Errorf("failed to parse %q of all-expression: %w", key, itemError)
				}

				what.in = item

			case common.Item:
				text, ok := value.(string)
				if !ok {
					return nil, value, fmt.Errorf("failed to parse %q of all-expression: expected string, got %T", key, value)
				}

				what.item = text

			case common.Index:
				text, ok := value.(string)
				if !ok {
					return nil, value, fmt.Errorf("failed to parse %q of all-expression: expected string, got %T", key, value)
				}

				what.index = text

			default:
				if what.expression != nil {
					return nil, script, fmt.Errorf("failed to parse all-expression: additional bool expression %q", key)
				}

				expression, errorScript, itemError := new(ExpressionList).ParseAny(map[string]any{key: value})
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse all-expression: %w", itemError)
				}

				boolExpression, ok := expression.(common.BoolExpression)
				if !ok {
					return nil, script, fmt.Errorf("all-expression contains non-bool expression: %w", itemError)
				}

				what.expression = boolExpression
			}
		}

	default:
		return nil, script, fmt.Errorf("failed to parse all-expression: expected map[string]any, got %T", script)
	}

	return what, nil, nil
}

func (what *AllExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *AllExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	oldItem := scope.PopItem()
	defer scope.SetItem(oldItem)

	inValue, errorEvalLiteral, evalError := what.in.EvalAny(scope)
	if evalError != nil {
		return common.EmptyBoolValue(), errorEvalLiteral, evalError
	}

	return what.evalBool(scope, inValue)
}

func (what *AllExpression) evalBool(scope *common.Scope, inValue common.Value) (*common.BoolValue, string, error) {
	oldItem := scope.PopItem()
	defer scope.SetItem(oldItem)

	inValue, errorEvalLiteral, evalError := what.in.EvalAny(scope)
	if evalError != nil {
		return common.EmptyBoolValue(), errorEvalLiteral, evalError
	}

	switch castValue := inValue.Value().(type) {
	case []any:
		if what.expression == nil {
			return common.SomeBoolValue(true, common.NewHistory("any value is good")), "", nil
		}

		for index, item := range castValue {
			if len(what.index) > 0 {
				scope.Set(what.index, common.SomeDecimalValue(decimal.NewFromInt(int64(index)), common.NewHistory("item %v of value", index).From(inValue.History())))
			}

			itemValue := scope.SetItem(common.SomeValue(item, common.NewHistory("item %v of value", index).From(inValue.History())))
			if len(what.item) > 0 {
				scope.Set(what.item, itemValue)
			}

			value, errorLiteral, expressionError := what.expression.EvalBool(scope)
			if expressionError != nil {
				return common.EmptyBoolValue(), errorLiteral, fmt.Errorf("error evaluating expression #%v of all-expression: %w", index+1, expressionError)
			}

			if !value.BoolValue() {
				return common.SomeBoolValue(false, common.NewHistory("item %v is not true", index).From(value.History())), "", nil
			}
		}

		return common.SomeBoolValue(true, common.NewHistory("all %d items are true", len(castValue)).From(inValue.History())), "", nil

	case []common.Value:
		if what.expression == nil {
			return common.SomeBoolValue(true, common.NewHistory("any value is good")), "", nil
		}

		for index, item := range castValue {
			if len(what.index) > 0 {
				scope.Set(what.index, common.SomeDecimalValue(decimal.NewFromInt(int64(index)), common.NewHistory("item %v of value", index).From(inValue.History())))
			}

			itemValue := scope.SetItem(common.SomeValue(item.Value(), common.NewHistory("item %v of value", index).From(inValue.History())))
			if len(what.item) > 0 {
				scope.Set(what.item, itemValue)
			}

			value, errorLiteral, expressionError := what.expression.EvalBool(scope)
			if expressionError != nil {
				return common.EmptyBoolValue(), errorLiteral, fmt.Errorf("error evaluating expression #%v of all-expression: %w", index+1, expressionError)
			}

			if !value.BoolValue() {
				return common.SomeBoolValue(false, common.NewHistory("item %v is not true", index).From(value.History())), "", nil
			}
		}

		return common.SomeBoolValue(true, common.NewHistory("all %d items are true", len(castValue)).From(inValue.History())), "", nil

	case map[string]any:
		if what.expression == nil {
			return common.SomeBoolValue(true, common.NewHistory("any value is good")), "", nil
		}

		for name, item := range castValue {
			if len(what.index) > 0 {
				scope.Set(what.index, common.SomeStringValue(name, common.NewHistory("item %q of value", name).From(inValue.History())))
			}

			itemValue := scope.SetItem(common.SomeValue(item, common.NewHistory("item %q of value", name).From(inValue.History())))
			if len(what.item) > 0 {
				scope.Set(what.item, itemValue)
			}

			value, errorLiteral, expressionError := what.expression.EvalBool(scope)
			if expressionError != nil {
				return common.EmptyBoolValue(), errorLiteral, fmt.Errorf("error evaluating expression %q of all-expression: %w", name, expressionError)
			}

			if !value.BoolValue() {
				return common.SomeBoolValue(false, common.NewHistory("item %q is not true", name).From(value.History())), "", nil
			}
		}

		return common.SomeBoolValue(true, common.NewHistory("all %d items are true", len(castValue)).From(inValue.History())), "", nil

	case common.Value:
		return what.evalBool(scope, common.SomeValue(castValue.Value(), inValue.History()))

	default:
		return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to eval all-expression: expected iterable type, got %T", inValue)
	}
}

func (what *AllExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *AllExpression) Literal() string {
	return what.literal
}
