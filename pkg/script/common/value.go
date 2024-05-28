package common

type Value interface {
	PlainValue() any
	Value() any
	History() History
}
