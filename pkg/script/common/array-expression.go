package common

type ArrayExpression interface {
	ParseArray(script any) (ArrayExpression, any, error)
	ParseAny(script any) (Expression, any, error)
	EvalArray(scope *Scope) (*ArrayValue, string, error)
	EvalAny(scope *Scope) (Value, string, error)
	Literal() string
}
