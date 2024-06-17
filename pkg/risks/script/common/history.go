package common

import (
	"strings"
)

type History []*Event

func NewHistory(item *Event) History {
	return new(History).New(item)
}

func (what History) New(item *Event) History {
	if item != nil {
		return append(History{item}, what...)
	}

	return what
}

func (what History) String() string {
	return strings.Join(what.Indented(0), "\n")
}

func (what History) Indented(level int) []string {
	lines := make([]string, 0)
	for _, item := range what {
		lines = append(lines, item.Indented(level)...)
	}

	return lines
}
