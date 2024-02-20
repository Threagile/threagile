package common

type ArrayExpression interface {
	ParseArray(script any) (ArrayExpression, any, error)
	ParseAny(script any) (Expression, any, error)
	EvalArray(scope *Scope) ([]any, string, error)
	EvalAny(scope *Scope) (any, string, error)
	Literal() string
}
