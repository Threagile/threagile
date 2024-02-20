package expressions

import (
	"fmt"
	"github.com/threagile/threagile/pkg/script/common"
)

type AndExpression struct {
	literal     string
	expressions []common.BoolExpression
}

func (what *AndExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	item, errorScript, itemError := new(ExpressionList).ParseAny(script)
	if itemError != nil {
		return nil, errorScript, fmt.Errorf("failed to parse and-expression list: %v", itemError)
	}

	switch item.(type) {
	case common.ExpressionList:
		for _, expression := range item.(common.ExpressionList).Expressions() {
			boolExpression, ok := expression.(common.BoolExpression)
			if !ok {
				return nil, script, fmt.Errorf("and-expression contains non-bool expression: %v", itemError)
			}

			what.expressions = append(what.expressions, boolExpression)
		}

	case common.BoolExpression:
		what.expressions = append(what.expressions, item.(common.BoolExpression))

	default:
		return nil, script, fmt.Errorf("and-expression has non-bool expression: %v", itemError)
	}

	return what, nil, nil
}

func (what *AndExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *AndExpression) EvalBool(scope *common.Scope) (bool, string, error) {
	for index, expression := range what.expressions {
		value, errorLiteral, evalError := expression.EvalBool(scope)
		if evalError != nil {
			return false, errorLiteral, fmt.Errorf("%q: error evaluating and-expression #%v: %v", what.literal, index+1, evalError)
		}

		if !value {
			return false, "", nil
		}
	}

	return true, "", nil
}

func (what *AndExpression) EvalAny(scope *common.Scope) (any, string, error) {
	return what.EvalBool(scope)
}

func (what *AndExpression) Literal() string {
	return what.literal
}
