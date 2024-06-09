package common

type ExplainStatement interface {
	Statement
	Eval(scope *Scope) string
}
