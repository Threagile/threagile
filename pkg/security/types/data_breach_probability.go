/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"strings"
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
	value = strings.TrimSpace(value)
	if value == "" {
		return Possible, err
	}

	for _, candidate := range DataBreachProbabilityValues() {
		if candidate.String() == value {
			return candidate.(DataBreachProbability), err
		}
	}
	return dataBreachProbability, fmt.Errorf("unable to parse into type: %v", value)
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

func (what DataBreachProbability) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *DataBreachProbability) UnmarshalJSON(data []byte) error {
	var text string
	unmarshalError := json.Unmarshal(data, &text)
	if unmarshalError != nil {
		return unmarshalError
	}

	value, findError := what.find(text)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what DataBreachProbability) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *DataBreachProbability) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what DataBreachProbability) find(value string) (DataBreachProbability, error) {
	for index, description := range DataBreachProbabilityTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return DataBreachProbability(index), nil
		}
	}

	return DataBreachProbability(0), fmt.Errorf("unknown data breach probability value %q", value)
}
