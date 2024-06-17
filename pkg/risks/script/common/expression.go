package common

type Expression interface {
	ParseAny(script any) (Expression, any, error)
	EvalAny(scope *Scope) (Value, string, error)
	Literal() string
}
