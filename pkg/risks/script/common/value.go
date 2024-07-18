package common

import (
	"github.com/threagile/threagile/pkg/risks/script/event"
)

type Value interface {
	event.Value
	PlainValue() any
	Value() any
}
