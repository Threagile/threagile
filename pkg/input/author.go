package input

import (
	"fmt"
	"sort"
	"strings"
)

type Author struct {
	Name       string `yaml:"name,omitempty" json:"name,omitempty"`
	Contact    string `yaml:"contact,omitempty" json:"contact,omitempty"`
	Homepage   string `yaml:"homepage,omitempty" json:"homepage,omitempty"`
}

func (what *Author) Merge(other Author) error {
	if len(what.Name) > 0 && !strings.EqualFold(what.Name, other.Name) {
		return fmt.Errorf("author name mismatch")
	}

	if len(what.Contact) > 0 && !strings.EqualFold(what.Contact, other.Contact) {
		return fmt.Errorf("author contact mismatch")
	}

	if len(what.Homepage) > 0 && !strings.EqualFold(what.Homepage, other.Homepage) {
		return fmt.Errorf("author homepage mismatch")
	}

	what.Name = other.Name
	what.Contact = other.Contact
	what.Homepage = other.Homepage

	return nil
}

func (what *Author) MergeList(list []Author) ([]Author, error) {
	sort.Slice(list, func(i int, j int) bool {
		return strings.Compare(list[i].Name, list[j].Name) < 0
	})

	if len(list) < 2 {
		return list, nil
	}

	first := list[0]
	tail, mergeError := what.MergeList(list[1:])
	if mergeError != nil {
		return nil, mergeError
	}

	newList := make([]Author, 1)
	newList[0] = first
	for _, second := range tail {
		if first.Match(second) {
			mergeError = first.Merge(second)
			if mergeError != nil {
				return nil, mergeError
			}
		} else {
			newList = append(newList, second)
		}
	}

	return newList, nil
}

func (what *Author) Match(other Author) bool {
	return strings.EqualFold(what.Name, other.Name)
}
