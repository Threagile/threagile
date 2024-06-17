package statements

import (
	"fmt"

	"github.com/threagile/threagile/pkg/risks/script/common"
	"github.com/threagile/threagile/pkg/risks/script/expressions"
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
					return nil, errorExpression, fmt.Errorf("failed to parse %q of loop-statement: %v", key, itemError)
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
					return nil, errorScript, fmt.Errorf("failed to parse %q of loop-statement: %v", key, itemError)
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
	oldIterator := scope.SwapIterator(nil)
	defer scope.SetIterator(oldIterator)

	value, errorEvalLiteral, evalError := what.in.EvalAny(scope)
	if evalError != nil {
		return errorEvalLiteral, evalError
	}

	switch castValue := value.(type) {
	case []any:
		for index, item := range castValue {
			if len(what.index) > 0 {
				scope.Set(what.index, index)
			}

			scope.SetIterator(item)
			if len(what.item) > 0 {
				scope.Set(what.item, item)
			}

			errorLiteral, runError := what.body.Run(scope)
			if runError != nil {
				return errorLiteral, fmt.Errorf("failed to run loop-statement for item #%d: %v", index+1, runError)
			}
		}

	case map[string]any:
		for name, item := range castValue {
			if len(what.index) > 0 {
				scope.Set(what.index, name)
			}

			scope.SetIterator(item)
			if len(what.item) > 0 {
				scope.Set(what.item, item)
			}

			errorLiteral, runError := what.body.Run(scope)
			if runError != nil {
				return errorLiteral, fmt.Errorf("failed to run loop-statement for item %q: %v", name, runError)
			}
		}

	default:
		return what.Literal(), fmt.Errorf("failed to run loop-statement: expected iterable type, got %T", value)
	}

	return "", nil
}

func (what *LoopStatement) Literal() string {
	return what.literal
}
