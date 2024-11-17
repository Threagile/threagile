package expressions

import (
	"fmt"

	"github.com/threagile/threagile/pkg/risks/script/common"
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
			return nil, errorScript, fmt.Errorf("failed to parse array-expression: %w", itemError)
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

func (what *ArrayExpression) EvalArray(scope *common.Scope) (*common.ArrayValue, string, error) {
	values := make([]common.Value, 0)
	for index, expression := range what.expressions.Expressions() {
		value, errorLiteral, evalError := expression.EvalAny(scope)
		if evalError != nil {
			return nil, errorLiteral, fmt.Errorf("%q: error evaluating array-expression #%v: %w", what.literal, index+1, evalError)
		}

		values = append(values, value)
	}

	return common.SomeArrayValue(values, common.NewEvent(common.NewValueProperty(values), common.NewPath("array value")).From(values...)), "", nil
}

func (what *ArrayExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalArray(scope)
}

func (what *ArrayExpression) Literal() string {
	return what.literal
}
