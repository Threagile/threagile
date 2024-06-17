package statements

import (
	"fmt"
	"github.com/threagile/threagile/pkg/risks/script/common"
	"github.com/threagile/threagile/pkg/risks/script/expressions"
)

type ExplainStatement struct {
	literal    string
	expression common.StringExpression
}

func (what *ExplainStatement) Parse(script any) (common.Statement, any, error) {
	what.literal = common.ToLiteral(script)

	expression, errorScript, parseError := new(expressions.ExpressionList).ParseAny(script)
	if parseError != nil {
		return nil, errorScript, fmt.Errorf("failed to parse explain-statement: %w", parseError)
	}

	switch castItem := expression.(type) {
	case common.StringExpression:
		what.expression = castItem

	default:
		return nil, script, fmt.Errorf("explain-statement has non-string expression of type %T", castItem)
	}

	return what, nil, nil
}

func (what *ExplainStatement) Run(scope *common.Scope) (string, error) {
	if scope.HasReturned {
		return "", nil
	}

	scope.Explain = what

	return "", nil
}

func (what *ExplainStatement) Eval(scope *common.Scope) string {
	value, _, _ := what.expression.EvalString(scope)

	return value.StringValue()
}

func (what *ExplainStatement) Literal() string {
	return what.literal
}
