package expressions

import (
	"fmt"
	"github.com/threagile/threagile/pkg/script/common"
)

type TrueExpression struct {
	literal    string
	expression common.BoolExpression
}

func (what *TrueExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	what.literal = common.ToLiteral(script)

	item, errorScript, itemError := new(ExpressionList).ParseAny(script.(map[string]any))
	if itemError != nil {
		return nil, errorScript, fmt.Errorf("failed to parse true-expression: %v", itemError)
	}

	switch item.(type) {
	case common.BoolExpression:
		what.expression = item.(common.BoolExpression)

	default:
		return nil, script, fmt.Errorf("true-expression has non-bool expression: %v", itemError)
	}

	return what, nil, nil
}

func (what *TrueExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *TrueExpression) EvalBool(scope *common.Scope) (bool, string, error) {
	value, errorLiteral, evalError := what.expression.EvalBool(scope)
	if evalError != nil {
		return false, errorLiteral, fmt.Errorf("%q: error evaluating true-expression: %v", what.literal, evalError)
	}

	return value, "", nil
}

func (what *TrueExpression) EvalAny(scope *common.Scope) (any, string, error) {
	return what.EvalBool(scope)
}

func (what *TrueExpression) Literal() string {
	return what.literal
}
