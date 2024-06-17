package expressions

import (
	"fmt"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

type FalseExpression struct {
	literal    string
	expression common.BoolExpression
}

func (what *FalseExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	item, errorScript, itemError := new(ExpressionList).ParseAny(script)
	if itemError != nil {
		return nil, errorScript, fmt.Errorf("failed to parse false-expression: %w", itemError)
	}

	switch castItem := item.(type) {
	case common.BoolExpression:
		what.expression = castItem

	default:
		return nil, script, fmt.Errorf("false-expression has non-bool expression: %w", itemError)
	}

	return what, nil, nil
}

func (what *FalseExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *FalseExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	value, errorLiteral, evalError := what.expression.EvalBool(scope)
	if evalError != nil {
		return common.EmptyBoolValue(), errorLiteral, fmt.Errorf("%q: error evaluating false-expression: %w", what.literal, evalError)
	}

	return common.SomeBoolValue(!value.BoolValue(), value.Event()), "", nil
}

func (what *FalseExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *FalseExpression) Literal() string {
	return what.literal
}
