package common

type ExpressionList interface {
	ParseExpression(script map[string]any) (Expression, any, error)
	ParseArray(script any) (ExpressionList, any, error)
	ParseAny(script any) (Expression, any, error)
	EvalAny(scope *Scope) (Value, string, error)
	Expressions() []Expression
	Literal() string
}
