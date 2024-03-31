/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
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
