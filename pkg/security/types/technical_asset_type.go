/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package types

import (
	"errors"
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
	return technicalAssetType, errors.New("Unable to parse into type: " + value)
}
