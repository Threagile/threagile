package types

import (
	"gopkg.in/yaml.v3"
	"time"
)

const (
	jsonDateFormat = `"2006-01-02"`
	yamlDateFormat = `2006-01-02`
)

type Date struct {
	time.Time
}

func (what Date) MarshalJSON() ([]byte, error) {
	return []byte(what.Format(jsonDateFormat)), nil
}

func (what *Date) UnmarshalJSON(bytes []byte) error {
	date, parseError := time.Parse(jsonDateFormat, string(bytes))
	if parseError != nil {
		return parseError
	}

	what.Time = date

	return nil
}

func (what Date) MarshalYAML() (interface{}, error) {
	return what.Format(yamlDateFormat), nil
}

func (what *Date) UnmarshalYAML(node *yaml.Node) error {
	date, parseError := time.Parse(yamlDateFormat, node.Value)
	if parseError != nil {
		return parseError
	}

	what.Time = date

	return nil
}
