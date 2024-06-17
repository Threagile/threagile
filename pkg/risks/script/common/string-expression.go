package common

type StringExpression interface {
	ParseString(script any) (StringExpression, any, error)
	ParseAny(script any) (Expression, any, error)
	EvalString(scope *Scope) (*StringValue, string, error)
	EvalAny(scope *Scope) (Value, string, error)
	Literal() string
}
