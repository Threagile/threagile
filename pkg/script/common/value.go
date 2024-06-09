package common

type Value interface {
	PlainValue() any
	Value() any
	Name() Path
	SetName(name ...string)
	Event() *Event
	Text() []string
}
