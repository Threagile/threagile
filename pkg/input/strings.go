package input

import (
	"fmt"
	"slices"
	"strings"
)

const (
	lineSeparator = "\n<br><br>\n"
)

type Strings struct {
}

func (what *Strings) MergeSingleton(first string, second string) (string, error) {
	if len(first) > 0 {
		if len(second) > 0 {
			if !strings.EqualFold(first, second) {
				return first, fmt.Errorf("conflicting string values: %q versus %q", first, second)
			}
		}

		return first, nil
	}

	return second, nil
}

func (what *Strings) MergeMultiline(first string, second string) string {
	text := first
	if len(first) > 0 {
		if len(second) > 0 && !strings.EqualFold(first, second) {
			text = text + lineSeparator + second
		}
	} else {
		text = second
	}

	return text
}

func (what *Strings) MergeMap(first map[string]string, second map[string]string) (map[string]string, error) {
	for mapKey, mapValue := range second {
		_, ok := first[mapKey]
		if ok {
			return nil, fmt.Errorf("duplicate item %q", mapKey)
		}

		first[mapKey] = mapValue
	}

	return first, nil
}

func (what *Strings) MergeUniqueSlice(first []string, second []string) []string {
	for _, item := range second {
		if !slices.Contains(first, item) {
			first = append(first, item)
		}
	}

	return first
}
