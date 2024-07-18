package event

import (
	"fmt"
	"strings"
)

type Path []string

func NewPath(path ...string) Path {
	return path[:]
}

func (what Path) String() string {
	if what == nil {
		return ""
	}

	path := make([]string, 0)
	for _, item := range what {
		path = append([]string{fmt.Sprintf("%v", item)}, path...)
	}

	return strings.Join(path, " of ")
}
