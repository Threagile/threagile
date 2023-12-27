/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"errors"
	"fmt"
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
	return dataBreachProbability, errors.New("Unable to parse into type: " + value)
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

func (what *DataBreachProbability) UnmarshalJSON([]byte) error {
	for index, description := range DataBreachProbabilityTypeDescription {
		if strings.ToLower(what.String()) == strings.ToLower(description.Name) {
			*what = DataBreachProbability(index)
			return nil
		}
	}

	return fmt.Errorf("unknown data breach probability value %q", int(*what))
}
