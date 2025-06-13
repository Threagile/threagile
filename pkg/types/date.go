package types

import (
	"time"

	"github.com/goccy/go-yaml"
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

func init() {
	yaml.RegisterCustomMarshaler[Date](func(what Date) ([]byte, error) {
		return what.MarshalJSON()
	})

	yaml.RegisterCustomUnmarshaler[Date](func(what *Date, data []byte) error {
		return what.UnmarshalJSON(data)
	})
}
