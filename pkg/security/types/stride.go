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

type STRIDE int

const (
	Spoofing STRIDE = iota
	Tampering
	Repudiation
	InformationDisclosure
	DenialOfService
	ElevationOfPrivilege
)

func STRIDEValues() []TypeEnum {
	return []TypeEnum{
		Spoofing,
		Tampering,
		Repudiation,
		InformationDisclosure,
		DenialOfService,
		ElevationOfPrivilege,
	}
}

var StrideTypeDescription = [...]TypeDescription{
	{"spoofing", "Spoofing - Authenticity"},
	{"tampering", "Tampering - Integrity"},
	{"repudiation", "Repudiation - Non-repudiability"},
	{"information-disclosure", "Information disclosure - Confidentiality"},
	{"denial-of-service", "Denial of service - Availability"},
	{"elevation-of-privilege", "Elevation of privilege - Authorization"},
}

func ParseSTRIDE(value string) (stride STRIDE, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range STRIDEValues() {
		if candidate.String() == value {
			return candidate.(STRIDE), err
		}
	}
	return stride, errors.New("Unable to parse into type: " + value)
}

func (what STRIDE) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return StrideTypeDescription[what].Name
}

func (what STRIDE) Explain() string {
	return StrideTypeDescription[what].Description
}

func (what STRIDE) Title() string {
	return [...]string{"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}[what]
}

func (what STRIDE) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *STRIDE) UnmarshalJSON([]byte) error {
	for index, description := range StrideTypeDescription {
		if strings.ToLower(what.String()) == strings.ToLower(description.Name) {
			*what = STRIDE(index)
			return nil
		}
	}

	return fmt.Errorf("unknown STRIDE value %q", int(*what))
}
