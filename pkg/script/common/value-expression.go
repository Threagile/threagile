package common

import "github.com/shopspring/decimal"

type ValueExpression interface {
	ParseArray(script any) (ArrayExpression, any, error)
	ParseBool(script any) (BoolExpression, any, error)
	ParseDecimal(script any) (DecimalExpression, any, error)
	ParseString(script any) (StringExpression, any, error)
	ParseValue(script any) (ValueExpression, any, error)
	ParseAny(script any) (Expression, any, error)
	EvalArray(scope *Scope) ([]any, string, error)
	EvalBool(scope *Scope) (bool, string, error)
	EvalDecimal(scope *Scope) (decimal.Decimal, string, error)
	EvalString(scope *Scope) (string, string, error)
	EvalAny(scope *Scope) (any, string, error)
	Literal() string
}
