package common

import "github.com/shopspring/decimal"

type DecimalExpression interface {
	ParseDecimal(script any) (DecimalExpression, any, error)
	ParseAny(script any) (Expression, any, error)
	EvalDecimal(scope *Scope) (decimal.Decimal, string, error)
	EvalAny(scope *Scope) (any, string, error)
	Literal() string
}
