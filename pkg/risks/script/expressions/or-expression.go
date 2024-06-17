package expressions

import (
	"fmt"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

type OrExpression struct {
	literal     string
	expressions []common.BoolExpression
}

func (what *OrExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	item, errorScript, itemError := new(ExpressionList).ParseAny(script)
	if itemError != nil {
		return nil, errorScript, fmt.Errorf("failed to parse or-expression list: %w", itemError)
	}

	switch castItem := item.(type) {
	case common.ExpressionList:
		for _, expression := range castItem.Expressions() {
			boolExpression, ok := expression.(common.BoolExpression)
			if !ok {
				return nil, script, fmt.Errorf("or-expression contains non-bool expression: %w", itemError)
			}

			what.expressions = append(what.expressions, boolExpression)
		}

	case common.BoolExpression:
		what.expressions = append(what.expressions, castItem)

	default:
		return nil, script, fmt.Errorf("or-expression has non-bool expression: %w", itemError)
	}

	return what, nil, nil
}

func (what *OrExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *OrExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	values := make([]common.Value, 0)
	for index, expression := range what.expressions {
		value, errorLiteral, evalError := expression.EvalBool(scope)
		if evalError != nil {
			return common.EmptyBoolValue(), errorLiteral, fmt.Errorf("%q: error evaluating or-expression #%v: %w", what.literal, index+1, evalError)
		}

		if value.BoolValue() {
			return common.SomeBoolValue(true, value.Event()), "", nil
		}

		values = append(values, value)
	}

	return common.SomeBoolValue(false, common.NewEvent(common.NewFalseProperty(), common.EmptyPath()).From(values...)), "", nil
}

func (what *OrExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *OrExpression) Literal() string {
	return what.literal
}
