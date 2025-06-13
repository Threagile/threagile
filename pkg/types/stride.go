/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
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
	return stride, fmt.Errorf("unable to parse into type: %v", value)
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
	return []byte(what.String()), nil
}

func (what *STRIDE) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))

	value, findError := what.find(text)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what STRIDE) find(value string) (STRIDE, error) {
	for index, description := range StrideTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return STRIDE(index), nil
		}
	}

	return STRIDE(0), fmt.Errorf("unknown STRIDE value %q", value)
}

func init() {
	yaml.RegisterCustomMarshaler[STRIDE](func(what STRIDE) ([]byte, error) {
		return []byte(what.String()), nil
	})

	yaml.RegisterCustomUnmarshaler[STRIDE](func(what *STRIDE, data []byte) error {
		value, findError := what.find(strings.TrimSpace(string(data)))
		if findError != nil {
			return findError
		}

		*what = value
		return nil
	})
}
