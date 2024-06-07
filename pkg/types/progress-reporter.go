package types

type ProgressReporter interface {
	Info(a ...any)
	Warn(a ...any)
	Error(a ...any)
	Infof(format string, a ...any)
	Warnf(format string, a ...any)
	Errorf(format string, a ...any)
}
