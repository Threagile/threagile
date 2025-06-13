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

type TechnicalAssetSize int

const (
	System TechnicalAssetSize = iota
	Service
	Application
	Component
)

func TechnicalAssetSizeValues() []TypeEnum {
	return []TypeEnum{
		System,
		Service,
		Application,
		Component,
	}
}

var TechnicalAssetSizeDescription = [...]TypeDescription{
	{"system", "A system consists of several services"},
	{"service", "A specific service (web, mail, ...)"},
	{"application", "A single application"},
	{"component", "A component of an application (smaller unit like a microservice)"},
}

func (what TechnicalAssetSize) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return TechnicalAssetSizeDescription[what].Name
}

func (what TechnicalAssetSize) Explain() string {
	return TechnicalAssetSizeDescription[what].Description
}

func ParseTechnicalAssetSize(value string) (technicalAssetSize TechnicalAssetSize, err error) {
	return TechnicalAssetSize(0).Find(value)
}

func (what TechnicalAssetSize) Find(value string) (TechnicalAssetSize, error) {
	for index, description := range TechnicalAssetSizeDescription {
		if strings.EqualFold(value, description.Name) {
			return TechnicalAssetSize(index), nil
		}
	}

	return TechnicalAssetSize(0), fmt.Errorf("unknown technical asset size value %q", value)
}

func (what TechnicalAssetSize) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *TechnicalAssetSize) UnmarshalJSON(data []byte) error {
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
	yaml.RegisterCustomMarshaler[TechnicalAssetSize](func(what TechnicalAssetSize) ([]byte, error) {
		return []byte(what.String()), nil
	})

	yaml.RegisterCustomUnmarshaler[TechnicalAssetSize](func(what *TechnicalAssetSize, data []byte) error {
		value, findError := what.Find(strings.TrimSpace(string(data)))
		if findError != nil {
			return findError
		}

		*what = value
		return nil
	})
}
