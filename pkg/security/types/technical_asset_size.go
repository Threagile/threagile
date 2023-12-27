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
	value = strings.TrimSpace(value)
	for _, candidate := range TechnicalAssetSizeValues() {
		if candidate.String() == value {
			return candidate.(TechnicalAssetSize), err
		}
	}
	return technicalAssetSize, errors.New("Unable to parse into type: " + value)
}

func (what TechnicalAssetSize) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *TechnicalAssetSize) UnmarshalJSON([]byte) error {
	for index, description := range TechnicalAssetSizeDescription {
		if strings.ToLower(what.String()) == strings.ToLower(description.Name) {
			*what = TechnicalAssetSize(index)
			return nil
		}
	}

	return fmt.Errorf("unknown technical asset size value %q", int(*what))
}
