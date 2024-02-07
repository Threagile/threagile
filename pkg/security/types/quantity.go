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

type Quantity int

const (
	VeryFew Quantity = iota
	Few
	Many
	VeryMany
)

func QuantityValues() []TypeEnum {
	return []TypeEnum{
		VeryFew,
		Few,
		Many,
		VeryMany,
	}
}

func ParseQuantity(value string) (quantity Quantity, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range QuantityValues() {
		if candidate.String() == value {
			return candidate.(Quantity), err
		}
	}
	return quantity, fmt.Errorf("unable to parse into type: %v", value)
}

var QuantityTypeDescription = [...]TypeDescription{
	{"very-few", "Very few"},
	{"few", "Few"},
	{"many", "Many"},
	{"very-many", "Very many"},
}

func (what Quantity) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return QuantityTypeDescription[what].Name
}

func (what Quantity) Explain() string {
	return QuantityTypeDescription[what].Description
}

func (what Quantity) Title() string {
	return [...]string{"very few", "few", "many", "very many"}[what]
}

func (what Quantity) QuantityFactor() float64 {
	// fibonacci starting at 1
	return [...]float64{1, 2, 3, 5}[what]
}

func (what Quantity) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *Quantity) UnmarshalJSON(data []byte) error {
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

func (what Quantity) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *Quantity) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what Quantity) find(value string) (Quantity, error) {
	for index, description := range QuantityTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return Quantity(index), nil
		}
	}

	return Quantity(0), fmt.Errorf("unknown quantity value %q", value)
}
