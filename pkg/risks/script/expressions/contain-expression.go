package expressions

import (
	"fmt"

	"github.com/threagile/threagile/pkg/risks/script/common"
	"github.com/threagile/threagile/pkg/risks/script/event"
)

type ContainExpression struct {
	literal string
	item    common.ValueExpression
	in      common.ValueExpression
	as      string
}

func (what *ContainExpression) ParseBool(script any) (common.BoolExpression, any, error) {
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

func (what *ContainExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *ContainExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
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

func (what *ContainExpression) evalBool(scope *common.Scope, item common.Value, inValue common.Value) (*common.BoolValue, string, error) {
	switch castValue := inValue.Value().(type) {
	case []any:
		events := make([]event.Event, 0)
		for index, value := range castValue {
			compareEvent, compareError := common.Compare(item, common.SomeValue(value, scope.Stack()), what.as, scope.Stack())
			if compareError != nil {
				return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to eval contains-expression: can't compare value to item #%v: %w", index+1, compareError)
			}

			if common.IsSame(compareEvent) {
				return common.SomeBoolValue(true, scope.Stack(), event.NewContain(inValue, item, compareEvent)), "", nil
			}

			events = append(events, compareEvent)
		}

		return common.SomeBoolValue(false, scope.Stack(), events...), "", nil

	case []common.Value:
		events := make([]event.Event, 0)
		for index, value := range castValue {
			compareEvent, compareError := common.Compare(item, value, what.as, scope.Stack())
			if compareError != nil {
				return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to eval contains-expression: can't compare value to item #%v: %w", index+1, compareError)
			}

			if common.IsSame(compareEvent) {
				return common.SomeBoolValue(true, scope.Stack(), event.NewContain(inValue, item, compareEvent)), "", nil
			}

			events = append(events, compareEvent)
		}

		return common.SomeBoolValue(false, scope.Stack(), events...), "", nil

	case map[string]any:
		events := make([]event.Event, 0)
		for name, value := range castValue {
			compareEvent, compareError := common.Compare(item, common.SomeValue(value, scope.Stack()), what.as, scope.Stack())
			if compareError != nil {
				return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to eval contains-expression: can't compare value to item %q: %w", name, compareError)
			}

			if common.IsSame(compareEvent) {
				return common.SomeBoolValue(true, scope.Stack(), event.NewContain(inValue, item, compareEvent)), "", nil
			}

			events = append(events, compareEvent)
		}

		return common.SomeBoolValue(false, scope.Stack(), events...), "", nil

	case common.Value:
		return what.evalBool(scope, item, castValue)

	default:
		return common.EmptyBoolValue(), "", fmt.Errorf("failed to eval contains-expression: expected iterable type, got %T", inValue)
	}
}

func (what *ContainExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *ContainExpression) Literal() string {
	return what.literal
}
