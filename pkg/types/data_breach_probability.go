/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
)

type DataBreachProbability int

const (
	Improbable DataBreachProbability = iota
	Possible
	Probable
)

func DataBreachProbabilityValues() []TypeEnum {
	return []TypeEnum{
		Improbable,
		Possible,
		Probable,
	}
}

var DataBreachProbabilityTypeDescription = [...]TypeDescription{
	{"improbable", "Improbable"},
	{"possible", "Possible"},
	{"probable", "Probable"},
}

func ParseDataBreachProbability(value string) (dataBreachProbability DataBreachProbability, err error) {
	return DataBreachProbability(0).Find(value)
}

func (what DataBreachProbability) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return DataBreachProbabilityTypeDescription[what].Name
}

func (what DataBreachProbability) Explain() string {
	return DataBreachProbabilityTypeDescription[what].Description
}

func (what DataBreachProbability) Title() string {
	return [...]string{"Improbable", "Possible", "Probable"}[what]
}

func (what DataBreachProbability) Find(value string) (DataBreachProbability, error) {
	if len(value) == 0 {
		return Possible, nil
	}

	for index, description := range DataBreachProbabilityTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return DataBreachProbability(index), nil
		}
	}

	return DataBreachProbability(0), fmt.Errorf("unknown data breach probability value %q", value)
}

func (what DataBreachProbability) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *DataBreachProbability) UnmarshalJSON(data []byte) error {
	var text string
	unmarshalError := json.Unmarshal(data, &text)
	if unmarshalError != nil {
		return unmarshalError
	}

	value, findError := what.Find(text)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func init() {
	yaml.RegisterCustomMarshaler[DataBreachProbability](func(what DataBreachProbability) ([]byte, error) {
		return []byte(what.String()), nil
	})

	yaml.RegisterCustomUnmarshaler[DataBreachProbability](func(what *DataBreachProbability, data []byte) error {
		value, findError := what.Find(strings.TrimSpace(string(data)))
		if findError != nil {
			return findError
		}

		*what = value
		return nil
	})
}
