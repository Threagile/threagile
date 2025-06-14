package input

import (
	"fmt"
	"github.com/goccy/go-yaml"
	"slices"
	"strings"
)

const (
	lineSeparator = "\n<br><br>\n"
)

type Strings struct {
}

func (what *Strings) MergeSingleton(config configReader, first string, second string) (string, bool, error) {
	if len(first) > 0 {
		if len(second) > 0 {
			if !strings.EqualFold(first, second) {
				if !config.GetMergeModels() {
					return first, false, fmt.Errorf("conflicting string values: %q versus %q", first, second)
				}

				return second, false, fmt.Errorf("conflicting string values: %q versus %q", first, second)
			}
		}

		return first, false, nil
	}

	return second, false, nil
}

func (what *Strings) MergeMultiline(_ configReader, first string, second string) string {
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

func (what *Strings) MergeMap(config configReader, first map[string]string, second map[string]string) (map[string]string, bool, error) {
	var hasConflict bool
	for mapKey, mapValue := range second {
		_, ok := first[mapKey]
		if ok {
			if !config.GetMergeModels() {
				return nil, true, fmt.Errorf("duplicate item %q", mapKey)
			}

			hasConflict = true
		}

		first[mapKey] = mapValue
	}

	if hasConflict {
		return first, false, fmt.Errorf("duplicate items")
	}

	return first, false, nil
}

func (what *Strings) MergeUniqueSlice(_ configReader, first []string, second []string) []string {
	for _, item := range second {
		if !slices.Contains(first, item) {
			first = append(first, item)
		}
	}

	return first
}

func (what *Strings) AddLineNumbers(script any) string {
	text, isString := script.(string)
	if !isString {
		data, _ := yaml.Marshal(script)
		text = string(data)
	}

	lines := strings.Split(text, "\n")
	for n, line := range lines {
		lines[n] = fmt.Sprintf("%3d:\t%v", n+1, line)
	}

	return strings.Join(lines, "\n")
}

func (what *Strings) IndentPrintf(level int, script any) string {
	text, isString := script.(string)
	if !isString {
		data, _ := yaml.Marshal(script)
		text = string(data)
	}

	lines := strings.Split(text, "\n")
	for n, line := range lines {
		lines[n] = strings.Repeat("    ", level) + line
	}

	return strings.Join(lines, "\n")
}

func (what *Strings) IndentLine(level int, format string, params ...any) string {
	return strings.Repeat("    ", level) + fmt.Sprintf(format, params...)
}
