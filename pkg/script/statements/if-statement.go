package statements

import (
	"fmt"
	"github.com/threagile/threagile/pkg/script/common"
	"github.com/threagile/threagile/pkg/script/expressions"
)

type IfStatement struct {
	literal    string
	expression common.BoolExpression
	yesPath    common.Statement
	noPath     common.Statement
}

func (what *IfStatement) Parse(script any) (common.Statement, any, error) {
	what.literal = common.ToLiteral(script)

	switch script.(type) {
	case map[string]any:
		for key, value := range script.(map[string]any) {
			switch key {
			case common.Then:
				item, errorScript, itemError := new(StatementList).Parse(value)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse %q of if-statement: %v", key, itemError)
				}

				what.yesPath = item

			case common.Else:
				item, errorScript, itemError := new(StatementList).Parse(value)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse %q of if-statement: %v", key, itemError)
				}

				what.noPath = item

			default:
				if what.expression != nil {
					return nil, script, fmt.Errorf("if-statement has multiple expressions")
				}

				expression := map[string]any{
					key: value,
				}

				item, errorScript, itemError := new(expressions.ExpressionList).ParseExpression(expression)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse expression of if-statement: %v", itemError)
				}

				boolItem, ok := item.(common.BoolExpression)
				if !ok {
					return nil, script, fmt.Errorf("expression of if-statement is not a bool expression: %v", itemError)
				}

				what.expression = boolItem
			}
		}

	default:
		return nil, script, fmt.Errorf("failed to parse if-statement: expected map[string]any, got %T", script)
	}

	return what, nil, nil
}

func (what *IfStatement) Run(scope *common.Scope) (string, error) {
	if what.expression == nil {
		return "", nil
	}

	value, errorLiteral, evalError := what.expression.EvalBool(scope)
	if evalError != nil {
		return errorLiteral, evalError
	}

	if value {
		if what.yesPath != nil {
			return what.yesPath.Run(scope)
		}
	} else {
		if what.noPath != nil {
			return what.noPath.Run(scope)
		}
	}

	return "", nil
}

func (what *IfStatement) Literal() string {
	return what.literal
}
