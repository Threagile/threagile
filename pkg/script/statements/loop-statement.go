package statements

import (
	"fmt"
	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/script/common"
	"github.com/threagile/threagile/pkg/script/expressions"
)

type LoopStatement struct {
	literal string
	in      common.ValueExpression
	item    string
	index   string
	body    common.Statement
}

func (what *LoopStatement) Parse(script any) (common.Statement, any, error) {
	what.literal = common.ToLiteral(script)

	switch script.(type) {
	case map[string]any:
		for key, value := range script.(map[string]any) {
			switch key {
			case common.In:
				item, errorExpression, itemError := new(expressions.ValueExpression).ParseValue(value)
				if itemError != nil {
					return nil, errorExpression, fmt.Errorf("failed to parse %q of loop-statement: %w", key, itemError)
				}

				what.in = item

			case common.Item:
				text, ok := value.(string)
				if !ok {
					return nil, value, fmt.Errorf("failed to parse %q of loop-statement: expected string, got %T", key, value)
				}

				what.item = text

			case common.Index:
				text, ok := value.(string)
				if !ok {
					return nil, value, fmt.Errorf("failed to parse %q of loop-statement: expected string, got %T", key, value)
				}

				what.index = text

			case common.Do:
				item, errorScript, itemError := new(StatementList).Parse(value)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse %q of loop-statement: %w", key, itemError)
				}

				what.body = item

			default:
				return nil, script, fmt.Errorf("failed to parse loop-statement: unexpected keyword %q", key)
			}
		}

	default:
		return nil, script, fmt.Errorf("failed to parse loop-statement: expected map[string]any, got %T", script)
	}

	return what, nil, nil
}

func (what *LoopStatement) Run(scope *common.Scope) (string, error) {
	oldIterator := scope.PopItem()
	defer scope.SetItem(oldIterator)

	value, errorEvalLiteral, evalError := what.in.EvalAny(scope)
	if evalError != nil {
		return errorEvalLiteral, evalError
	}

	return what.run(scope, value)
}

func (what *LoopStatement) run(scope *common.Scope, value common.Value) (string, error) {
	switch castValue := value.Value().(type) {
	case []any:
		for index, item := range castValue {
			if len(what.index) > 0 {
				scope.Set(what.index, common.SomeDecimalValue(decimal.NewFromInt(int64(index)), common.NewHistory("index").From(value.History())))
			}

			itemValue := scope.SetItem(common.SomeValue(item, common.NewHistory("item #%d", index).From(value.History())))
			if len(what.item) > 0 {
				scope.Set(what.item, itemValue)
			}

			errorLiteral, runError := what.body.Run(scope)
			if runError != nil {
				return errorLiteral, fmt.Errorf("failed to run loop-statement for item #%d: %w", index+1, runError)
			}
		}

	case []common.Value:
		for index, item := range castValue {
			if len(what.index) > 0 {
				scope.Set(what.index, common.SomeDecimalValue(decimal.NewFromInt(int64(index)), common.NewHistory("index").From(value.History())))
			}

			itemValue := scope.SetItem(common.SomeValue(item.Value(), common.NewHistory("item #%d", index).From(value.History())))
			if len(what.item) > 0 {
				scope.Set(what.item, itemValue)
			}

			errorLiteral, runError := what.body.Run(scope)
			if runError != nil {
				return errorLiteral, fmt.Errorf("failed to run loop-statement for item #%d: %w", index+1, runError)
			}
		}

	case map[string]any:
		for name, item := range castValue {
			if len(what.index) > 0 {
				scope.Set(what.index, common.SomeStringValue(name, common.NewHistory("index").From(value.History())))
			}

			itemValue := scope.SetItem(common.SomeValue(item, common.NewHistory("item %q", name).From(value.History())))
			if len(what.item) > 0 {
				scope.Set(what.item, itemValue)
			}

			errorLiteral, runError := what.body.Run(scope)
			if runError != nil {
				return errorLiteral, fmt.Errorf("failed to run loop-statement for item %q: %w", name, runError)
			}
		}

	case common.Value:
		return what.run(scope, common.SomeValue(castValue.Value(), value.History()))

	default:
		return what.Literal(), fmt.Errorf("failed to run loop-statement: expected iterable type, got %T", value)
	}

	return "", nil
}

func (what *LoopStatement) Literal() string {
	return what.literal
}
