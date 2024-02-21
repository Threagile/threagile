package expressions

import (
	"fmt"
	"github.com/threagile/threagile/pkg/script/common"
)

type FalseExpression struct {
	literal    string
	expression common.BoolExpression
}

func (what *FalseExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	item, errorScript, itemError := new(ExpressionList).ParseAny(script)
	if itemError != nil {
		return nil, errorScript, fmt.Errorf("failed to parse false-expression: %v", itemError)
	}

	switch castItem := item.(type) {
	case common.BoolExpression:
		what.expression = castItem

	default:
		return nil, script, fmt.Errorf("false-expression has non-bool expression: %v", itemError)
	}

	return what, nil, nil
}

func (what *FalseExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *FalseExpression) EvalBool(scope *common.Scope) (bool, string, error) {
	value, errorLiteral, evalError := what.expression.EvalBool(scope)
	if evalError != nil {
		return false, errorLiteral, fmt.Errorf("%q: error evaluating false-expression: %v", what.literal, evalError)
	}

	return !value, "", nil
}

func (what *FalseExpression) EvalAny(scope *common.Scope) (any, string, error) {
	return what.EvalBool(scope)
}

func (what *FalseExpression) Literal() string {
	return what.literal
}
