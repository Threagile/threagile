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

type TechnicalAssetType int

const (
	ExternalEntity TechnicalAssetType = iota
	Process
	Datastore
)

func TechnicalAssetTypeValues() []TypeEnum {
	return []TypeEnum{
		ExternalEntity,
		Process,
		Datastore,
	}
}

var TechnicalAssetTypeDescription = [...]TypeDescription{
	{"external-entity", "This asset is hosted and managed by a third party"},
	{"process", "A software process"},
	{"datastore", "This asset stores data"},
}

func (what TechnicalAssetType) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return TechnicalAssetTypeDescription[what].Name
}

func (what TechnicalAssetType) Explain() string {
	return TechnicalAssetTypeDescription[what].Description
}

func ParseTechnicalAssetType(value string) (technicalAssetType TechnicalAssetType, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range TechnicalAssetTypeValues() {
		if candidate.String() == value {
			return candidate.(TechnicalAssetType), err
		}
	}
	return technicalAssetType, fmt.Errorf("unable to parse into type: %v", value)
}

func (what TechnicalAssetType) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *TechnicalAssetType) UnmarshalJSON(data []byte) error {
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

func (what TechnicalAssetType) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *TechnicalAssetType) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what TechnicalAssetType) find(value string) (TechnicalAssetType, error) {
	for index, description := range TechnicalAssetTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return TechnicalAssetType(index), nil
		}
	}

	return TechnicalAssetType(0), fmt.Errorf("unknown technical asset type value %q", value)
}
