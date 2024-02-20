package statements

import (
	"fmt"
	"github.com/threagile/threagile/pkg/script/common"
	"github.com/threagile/threagile/pkg/script/expressions"
)

type ReturnStatement struct {
	literal      string
	expression   common.Expression
	returnValues []common.Value
}

func (what *ReturnStatement) Parse(script any) (common.Statement, any, error) {
	what.literal = common.ToLiteral(script)

	item, errorScript, itemError := new(expressions.ExpressionList).ParseAny(script)
	if itemError != nil {
		return nil, errorScript, fmt.Errorf("failed to parse expressions if-statement: %v", itemError)
	}

	what.expression = item

	return what, nil, nil
}

func (what *ReturnStatement) Run(scope *common.Scope) (string, error) {
	if what.expression == nil {
		return "", nil
	}

	value, errorLiteral, evalError := what.expression.EvalAny(scope)
	if evalError != nil {
		return errorLiteral, evalError
	}

	scope.SetReturnValue(value)

	return "", nil
}

func (what *ReturnStatement) Literal() string {
	return what.literal
}
