package expressions

import (
	"fmt"

	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/risks/script/common"
	"github.com/threagile/threagile/pkg/risks/script/event"
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
	if what.expression == nil {
		return common.SomeBoolValue(true, scope.Stack()), "", nil
	}

	switch castValue := inValue.Value().(type) {
	case []any:
		events := make([]event.Event, 0)
		for index, item := range castValue {
			indexValue := common.SomeDecimalValue(decimal.NewFromInt(int64(index)), scope.Stack())
			itemValue := common.SomeValueWithPath(item, inValue.Path(), scope.Stack(), event.NewValueEvent(inValue))
			isDone, value, errorLiteral, expressionError := what.evalBoolOnce(scope, indexValue, itemValue, fmt.Sprintf("#%v", index))
			if isDone {
				return common.SomeBoolValue(false, scope.Stack(), event.NewValueEvent(value)), errorLiteral, expressionError
			}

			events = append(events, event.NewValueEvent(value))
		}

		return common.SomeBoolValue(true, scope.Stack(), events...), "", nil

	case []common.Value:
		events := make([]event.Event, 0)
		for index, item := range castValue {
			indexValue := common.SomeDecimalValue(decimal.NewFromInt(int64(index)), scope.Stack())
			itemValue := common.SomeValueWithPath(item, inValue.Path(), scope.Stack(), event.NewValueEvent(inValue))
			isDone, value, errorLiteral, expressionError := what.evalBoolOnce(scope, indexValue, itemValue, fmt.Sprintf("#%v", index))
			if isDone {
				return common.SomeBoolValue(false, scope.Stack(), event.NewValueEvent(value)), errorLiteral, expressionError
			}

			events = append(events, event.NewValueEvent(value))
		}

		return common.SomeBoolValue(true, scope.Stack(), events...), "", nil

	case map[string]any:
		events := make([]event.Event, 0)
		for name, item := range castValue {
			indexValue := common.SomeStringValue(name, scope.Stack())
			itemValue := common.SomeValueWithPath(item, inValue.Path(), scope.Stack(), event.NewValueEvent(inValue))
			isDone, value, errorLiteral, expressionError := what.evalBoolOnce(scope, indexValue, itemValue, fmt.Sprintf("%q", name))
			if isDone {
				return common.SomeBoolValue(false, scope.Stack(), event.NewValueEvent(value)), errorLiteral, expressionError
			}

			events = append(events, event.NewValueEvent(value))
		}

		return common.SomeBoolValue(true, scope.Stack(), events...), "", nil

	case common.Value:
		return what.evalBool(scope, castValue)

	default:
		return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to eval all-expression: expected iterable type, got %T", inValue)
	}
}

func (what *AllExpression) evalBoolOnce(scope *common.Scope, indexValue common.Value, itemValue common.Value, index string) (bool, common.Value, string, error) {
	if len(what.index) > 0 {
		scope.Set(what.index, indexValue)
	}

	scope.SetItem(itemValue)
	if len(what.item) > 0 {
		scope.Set(what.item, itemValue)
	}

	value, errorLiteral, expressionError := what.expression.EvalBool(scope)
	if expressionError != nil {
		return true, value, errorLiteral, fmt.Errorf("error evaluating expression %v of all-expression: %w", index, expressionError)
	}

	if !value.BoolValue() {
		return true, value, "", nil
	}

	return false, value, "", nil
}

func (what *AllExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *AllExpression) Literal() string {
	return what.literal
}
