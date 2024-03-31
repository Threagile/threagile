/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
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
