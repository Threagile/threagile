package common

type BoolExpression interface {
	ParseBool(script any) (BoolExpression, any, error)
	ParseAny(script any) (Expression, any, error)
	EvalBool(scope *Scope) (*BoolValue, string, error)
	EvalAny(scope *Scope) (Value, string, error)
	Literal() string
}
