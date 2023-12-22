/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package types

import "encoding/json"

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
