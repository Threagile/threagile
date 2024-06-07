package common

type Expression interface {
	ParseAny(script any) (Expression, any, error)
	EvalAny(scope *Scope) (any, string, error)
	Literal() string
}
