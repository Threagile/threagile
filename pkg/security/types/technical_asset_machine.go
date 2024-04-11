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

type TechnicalAssetMachine int

const (
	Physical TechnicalAssetMachine = iota
	Virtual
	Container
	Serverless
)

func TechnicalAssetMachineValues() []TypeEnum {
	return []TypeEnum{
		Physical,
		Virtual,
		Container,
		Serverless,
	}
}

var TechnicalAssetMachineTypeDescription = [...]TypeDescription{
	{"physical", "A physical machine"},
	{"virtual", "A virtual machine"},
	{"container", "A container"},
	{"serverless", "A serverless application"},
}

func ParseTechnicalAssetMachine(value string) (technicalAssetMachine TechnicalAssetMachine, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range TechnicalAssetMachineValues() {
		if candidate.String() == value {
			return candidate.(TechnicalAssetMachine), err
		}
	}
	return technicalAssetMachine, fmt.Errorf("unable to parse into type: %v", value)
}

func (what TechnicalAssetMachine) String() string {
	return TechnicalAssetMachineTypeDescription[what].Name
}

func (what TechnicalAssetMachine) Explain() string {
	return TechnicalAssetMachineTypeDescription[what].Description
}

func (what TechnicalAssetMachine) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *TechnicalAssetMachine) UnmarshalJSON(data []byte) error {
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

func (what TechnicalAssetMachine) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *TechnicalAssetMachine) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what TechnicalAssetMachine) find(value string) (TechnicalAssetMachine, error) {
	for index, description := range TechnicalAssetMachineTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return TechnicalAssetMachine(index), nil
		}
	}

	return TechnicalAssetMachine(0), fmt.Errorf("unknown technical asset machine value %q", value)
}
