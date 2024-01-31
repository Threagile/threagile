package types

import (
	"gopkg.in/yaml.v3"
	"time"
)

type Date struct {
	time.Time
}

func (what Date) MarshalJSON() ([]byte, error) {
	return []byte(what.Format(`"2006-01-02"`)), nil
}

func (what *Date) UnmarshalJSON(bytes []byte) error {
	date, parseError := time.Parse(`"2006-01-02"`, string(bytes))
	if parseError != nil {
		return parseError
	}

	what.Time = date

	return nil
}

func (what Date) MarshalYAML() (interface{}, error) {
	return what.Format(`2006-01-02`), nil
}

func (what *Date) UnmarshalYAML(node *yaml.Node) error {
	date, parseError := time.Parse(`2006-01-02`, node.Value)
	if parseError != nil {
		return parseError
	}

	what.Time = date

	return nil
}
