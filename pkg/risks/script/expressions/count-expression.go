package expressions

import (
	"fmt"

	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/risks/script/common"
	"github.com/threagile/threagile/pkg/risks/script/event"
)

type CountExpression struct {
	literal    string
	in         common.ValueExpression
	item       string
	index      string
	expression common.BoolExpression
}

func (what *CountExpression) ParseDecimal(script any) (common.DecimalExpression, any, error) {
	what.literal = common.ToLiteral(script)

	switch script.(type) {
	case map[string]any:
		for key, value := range script.(map[string]any) {
			switch key {
			case common.In:
				item, errorExpression, itemError := new(ValueExpression).ParseValue(value)
				if itemError != nil {
					return nil, errorExpression, fmt.Errorf("failed to parse %q of count-expression: %w", key, itemError)
				}

				what.in = item

			case common.Item:
				text, ok := value.(string)
				if !ok {
					return nil, value, fmt.Errorf("failed to parse %q of count-expression: expected string, got %T", key, value)
				}

				what.item = text

			case common.Index:
				text, ok := value.(string)
				if !ok {
					return nil, value, fmt.Errorf("failed to parse %q of count-expression: expected string, got %T", key, value)
				}

				what.index = text

			default:
				if what.expression != nil {
					return nil, script, fmt.Errorf("failed to parse count-expression: additional bool expression %q", key)
				}

				expression, errorScript, itemError := new(ExpressionList).ParseAny(map[string]any{key: value})
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse count-expression: %w", itemError)
				}

				boolExpression, ok := expression.(common.BoolExpression)
				if !ok {
					return nil, script, fmt.Errorf("count-expression contains non-bool expression: %w", itemError)
				}

				what.expression = boolExpression
			}
		}

	default:
		return nil, script, fmt.Errorf("failed to parse count-expression: expected map[string]any, got %T", script)
	}

	return what, nil, nil
}

func (what *CountExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseDecimal(script)
}

func (what *CountExpression) EvalDecimal(scope *common.Scope) (*common.DecimalValue, string, error) {
	oldItem := scope.PopItem()
	defer scope.SetItem(oldItem)

	inValue, errorEvalLiteral, evalError := what.in.EvalAny(scope)
	if evalError != nil {
		return common.EmptyDecimalValue(), errorEvalLiteral, evalError
	}

	return what.evalDecimal(scope, inValue)
}

func (what *CountExpression) evalDecimal(scope *common.Scope, inValue common.Value) (*common.DecimalValue, string, error) {
	switch castValue := inValue.Value().(type) {
	case []any:
		if what.expression == nil {
			return common.SomeDecimalValue(decimal.NewFromInt(int64(len(castValue))), scope.Stack()), "", nil
		}

		events := make([]event.Event, 0)
		var count int64 = 0
		for index, item := range castValue {
			indexValue := common.SomeDecimalValue(decimal.NewFromInt(int64(index)), scope.Stack())
			itemValue := common.SomeValueWithPath(item, inValue.Path(), scope.Stack(), event.NewValueEvent(inValue))
			value, errorLiteral, expressionError := what.evalDecimalOnce(scope, indexValue, itemValue, fmt.Sprintf("#%v", index))
			if expressionError != nil {
				return common.EmptyDecimalValue(), errorLiteral, fmt.Errorf("error evaluating expression #%v of all-expression: %w", index+1, expressionError)
			}

			if value.BoolValue() {
				events = append(events, event.NewValueEvent(value))
				count++
			}
		}

		return common.SomeDecimalValue(decimal.NewFromInt(count), scope.Stack(), events...), "", nil

	case []common.Value:
		if what.expression == nil {
			return common.SomeDecimalValue(decimal.NewFromInt(int64(len(castValue))), scope.Stack()), "", nil
		}

		events := make([]event.Event, 0)
		var count int64 = 0
		for index, item := range castValue {
			indexValue := common.SomeDecimalValue(decimal.NewFromInt(int64(index)), scope.Stack())
			itemValue := common.SomeValueWithPath(item, inValue.Path(), scope.Stack(), event.NewValueEvent(inValue))
			value, errorLiteral, expressionError := what.evalDecimalOnce(scope, indexValue, itemValue, fmt.Sprintf("#%v", index))
			if expressionError != nil {
				return common.EmptyDecimalValue(), errorLiteral, expressionError
			}

			if value.BoolValue() {
				events = append(events, event.NewValueEvent(value))
				count++
			}
		}

		return common.SomeDecimalValue(decimal.NewFromInt(count), scope.Stack(), events...), "", nil

	case map[string]any:
		if what.expression == nil {
			return common.SomeDecimalValue(decimal.NewFromInt(int64(len(castValue))), scope.Stack()), "", nil
		}

		events := make([]event.Event, 0)
		var count int64 = 0
		for name, item := range castValue {
			indexValue := common.SomeStringValue(name, scope.Stack())
			itemValue := common.SomeValueWithPath(item, inValue.Path(), scope.Stack(), event.NewValueEvent(inValue))
			value, errorLiteral, expressionError := what.evalDecimalOnce(scope, indexValue, itemValue, fmt.Sprintf("%q", name))
			if expressionError != nil {
				return common.EmptyDecimalValue(), errorLiteral, expressionError
			}

			if value.BoolValue() {
				events = append(events, event.NewValueEvent(value))
				count++
			}
		}

		return common.SomeDecimalValue(decimal.NewFromInt(count), scope.Stack(), events...), "", nil

	case common.Value:
		return what.evalDecimal(scope, castValue)

	default:
		return common.EmptyDecimalValue(), what.Literal(), fmt.Errorf("failed to eval all-expression: expected iterable type, got %T", inValue)
	}
}

func (what *CountExpression) evalDecimalOnce(scope *common.Scope, indexValue common.Value, itemValue common.Value, index string) (*common.BoolValue, string, error) {
	if len(what.index) > 0 {
		scope.Set(what.index, indexValue)
	}

	scope.SetItem(itemValue)
	if len(what.item) > 0 {
		scope.Set(what.item, itemValue)
	}

	value, errorLiteral, expressionError := what.expression.EvalBool(scope)
	if expressionError != nil {
		return value, errorLiteral, fmt.Errorf("error evaluating expression %v of all-expression: %w", index, expressionError)
	}

	return value, "", nil
}

func (what *CountExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalDecimal(scope)
}

func (what *CountExpression) Literal() string {
	return what.literal
}
