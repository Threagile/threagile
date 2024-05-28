package common

type DecimalExpression interface {
	ParseDecimal(script any) (DecimalExpression, any, error)
	ParseAny(script any) (Expression, any, error)
	EvalDecimal(scope *Scope) (*DecimalValue, string, error)
	EvalAny(scope *Scope) (Value, string, error)
	Literal() string
}
