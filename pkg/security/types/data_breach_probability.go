/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package types

import "encoding/json"

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
