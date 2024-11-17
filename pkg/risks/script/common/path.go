package common

import (
	"fmt"
	"strings"
)

type Path struct {
	Path []string
}

func NewPath(path ...string) *Path {
	return new(Path).SetPath(path...)
}

func EmptyPath() *Path {
	return new(Path)
}

func (what *Path) Copy() *Path {
	if what == nil {
		return what
	}

	return &Path{
		Path: what.Path[:],
	}
}

func (what *Path) SetPath(path ...string) *Path {
	if what == nil {
		return what
	}

	what.Path = path
	return what
}

func (what *Path) AddPathParent(path ...string) *Path {
	if what == nil {
		return what
	}

	what.Path = append(path, what.Path...)
	return what
}

func (what *Path) AddPathLeaf(path ...string) *Path {
	if what == nil {
		return what
	}

	what.Path = append(what.Path, path...)
	return what
}

func (what *Path) String() string {
	if what == nil {
		return ""
	}

	path := make([]string, 0)
	for _, item := range what.Path {
		path = append([]string{fmt.Sprintf("%v", item)}, path...)
	}

	return strings.Join(path, " of ")
}
