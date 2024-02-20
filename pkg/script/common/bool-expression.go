package common

type BoolExpression interface {
	ParseBool(script any) (BoolExpression, any, error)
	ParseAny(script any) (Expression, any, error)
	EvalBool(scope *Scope) (bool, string, error)
	EvalAny(scope *Scope) (any, string, error)
	Literal() string
}
