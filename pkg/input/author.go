package input

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Author struct {
	SourceFile string `yaml:"source-file,omitempty" json:"source-file,omitempty"`
	Name       string `yaml:"name,omitempty" json:"name,omitempty"`
	Contact    string `yaml:"contact,omitempty" json:"contact,omitempty"`
	Homepage   string `yaml:"homepage,omitempty" json:"homepage,omitempty"`
}

func (what *Author) Merge(config configReader, other Author) (bool, error) {
	var mergeErrors error
	if len(what.Name) > 0 && !strings.EqualFold(what.Name, other.Name) {
		if !config.GetMergeModels() {
			return false, fmt.Errorf("author name mismatch")
		}

		mergeErrors = errors.Join(fmt.Errorf("author name mismatch"), mergeErrors)
	}

	if len(what.Contact) > 0 && !strings.EqualFold(what.Contact, other.Contact) {
		if !config.GetMergeModels() {
			return false, fmt.Errorf("author contact mismatch")
		}

		mergeErrors = errors.Join(fmt.Errorf("author contact mismatch"), mergeErrors)
	}

	if len(what.Homepage) > 0 && !strings.EqualFold(what.Homepage, other.Homepage) {
		if !config.GetMergeModels() {
			return false, fmt.Errorf("author homepage mismatch")
		}

		mergeErrors = errors.Join(fmt.Errorf("author homepage mismatch"), mergeErrors)
	}

	what.Name = other.Name
	what.Contact = other.Contact
	what.Homepage = other.Homepage

	return false, mergeErrors
}

func (what *Author) MergeList(config configReader, list []Author) ([]Author, bool, error) {
	sort.Slice(list, func(i int, j int) bool {
		return strings.Compare(list[i].Name, list[j].Name) < 0
	})

	if len(list) < 2 {
		return list, false, nil
	}

	var mergeErrors error
	first := list[0]
	tail, isFatal, mergeError := what.MergeList(config, list[1:])
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return nil, isFatal, mergeError
		}

		mergeErrors = mergeError
	}

	newList := make([]Author, 1)
	newList[0] = first
	for _, second := range tail {
		if first.Match(second) {
			isFatal, mergeError = first.Merge(config, second)
			if mergeError != nil {
				mergeErrors = errors.Join(mergeError, mergeErrors)
				if !config.GetMergeModels() || isFatal {
					return nil, isFatal, mergeErrors
				}
			}

			newList[0] = first
		} else {
			newList = append(newList, second)
		}
	}

	return newList, isFatal, mergeErrors
}

func (what *Author) Match(other Author) bool {
	return strings.EqualFold(what.Name, other.Name)
}
