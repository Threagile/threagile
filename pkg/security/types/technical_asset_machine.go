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
	return technicalAssetMachine, errors.New("Unable to parse into type: " + value)
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

func (what *TechnicalAssetMachine) UnmarshalJSON([]byte) error {
	for index, description := range TechnicalAssetMachineTypeDescription {
		if strings.ToLower(what.String()) == strings.ToLower(description.Name) {
			*what = TechnicalAssetMachine(index)
			return nil
		}
	}

	return fmt.Errorf("unknown technical asset machine value %q", int(*what))
}
