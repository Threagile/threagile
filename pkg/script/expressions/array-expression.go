package expressions

import (
	"fmt"

	"github.com/threagile/threagile/pkg/script/common"
)

type ArrayExpression struct {
	literal     string
	expressions common.ExpressionList
}

func (what *ArrayExpression) ParseArray(script any) (common.ArrayExpression, any, error) {
	what.literal = common.ToLiteral(script)

	switch castScript := script.(type) {
	case map[string]any:
		expressions := new(ExpressionList)
		_, errorScript, itemError := expressions.ParseAny(castScript)
		if itemError != nil {
			return nil, errorScript, fmt.Errorf("failed to parse array-expression: %v", itemError)
		}

		what.expressions = expressions

	default:
		return nil, script, fmt.Errorf("unexpected array-expression format %T", script)
	}

	return what, nil, nil
}

func (what *ArrayExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseArray(script)
}

func (what *ArrayExpression) EvalArray(scope *common.Scope) ([]any, string, error) {
	values := make([]any, 0)
	for index, expression := range what.expressions.Expressions() {
		value, errorLiteral, evalError := expression.EvalAny(scope)
		if evalError != nil {
			return nil, errorLiteral, fmt.Errorf("%q: error evaluating array-expression #%v: %v", what.literal, index+1, evalError)
		}

		values = append(values, value)
	}

	return values, "", nil
}

func (what *ArrayExpression) EvalAny(scope *common.Scope) (any, string, error) {
	return what.EvalArray(scope)
}

func (what *ArrayExpression) Literal() string {
	return what.literal
}
