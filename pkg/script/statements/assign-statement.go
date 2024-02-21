package statements

import (
	"fmt"
	"github.com/threagile/threagile/pkg/script/common"
	"github.com/threagile/threagile/pkg/script/expressions"
)

type AssignStatement struct {
	literal string
	items   map[string]common.Expression
}

func (what *AssignStatement) Parse(script any) (common.Statement, any, error) {
	what.literal = common.ToLiteral(script)

	if what.items == nil {
		what.items = make(map[string]common.Expression)
	}

	switch castScript := script.(type) {
	case map[string]any:
		return what.parse(castScript)

	case []any:
		for _, statement := range castScript {
			_, errorScript, itemError := what.Parse(statement)
			if itemError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse assign-statement: %v", itemError)
			}
		}

	default:
		return nil, script, fmt.Errorf("unexpected assign-statement format %T", script)
	}

	return what, nil, nil
}

func (what *AssignStatement) parse(script map[string]any) (common.Statement, any, error) {
	for key, value := range script {
		expression, errorScript, parseError := new(expressions.ExpressionList).ParseAny(value)
		if parseError != nil {
			return nil, errorScript, fmt.Errorf("failed to parse %q of assign-statement: %v", key, parseError)
		}

		what.items[key] = expression
	}

	return what, nil, nil
}

func (what *AssignStatement) Run(scope *common.Scope) (string, error) {
	for name, item := range what.items {
		value, errorLiteral, evalError := item.EvalAny(scope)
		if evalError != nil {
			return errorLiteral, fmt.Errorf("failed to eval %q of assign-statement: %v", name, evalError)
		}

		scope.Set(name, value)
	}

	return "", nil
}

func (what *AssignStatement) Literal() string {
	return what.literal
}
