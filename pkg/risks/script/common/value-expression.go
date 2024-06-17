package common

type ValueExpression interface {
	ParseArray(script any) (ArrayExpression, any, error)
	ParseBool(script any) (BoolExpression, any, error)
	ParseDecimal(script any) (DecimalExpression, any, error)
	ParseString(script any) (StringExpression, any, error)
	ParseAny(script any) (Expression, any, error)
	EvalArray(scope *Scope) (*ArrayValue, string, error)
	EvalBool(scope *Scope) (*BoolValue, string, error)
	EvalDecimal(scope *Scope) (*DecimalValue, string, error)
	EvalString(scope *Scope) (*StringValue, string, error)
	EvalAny(scope *Scope) (Value, string, error)
	Literal() string
}
