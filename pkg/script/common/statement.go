package common

type Statement interface {
	Run(scope *Scope) (string, error)
	Literal() string
}
