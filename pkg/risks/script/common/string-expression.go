package common

type StringExpression interface {
	ParseString(script any) (StringExpression, any, error)
	ParseAny(script any) (Expression, any, error)
	EvalString(scope *Scope) (string, string, error)
	EvalAny(scope *Scope) (any, string, error)
	Literal() string
}
