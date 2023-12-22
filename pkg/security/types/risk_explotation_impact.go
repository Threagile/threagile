/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package types

import "encoding/json"

type RiskExploitationImpact int

const (
	LowImpact RiskExploitationImpact = iota
	MediumImpact
	HighImpact
	VeryHighImpact
)

func RiskExploitationImpactValues() []TypeEnum {
	return []TypeEnum{
		LowImpact,
		MediumImpact,
		HighImpact,
		VeryHighImpact,
	}
}

var RiskExploitationImpactTypeDescription = [...]TypeDescription{
	{"low", "Low"},
	{"medium", "Medium"},
	{"high", "High"},
	{"very-high", "Very High"},
}

func (what RiskExploitationImpact) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return RiskExploitationImpactTypeDescription[what].Name
}

func (what RiskExploitationImpact) Explain() string {
	return RiskExploitationImpactTypeDescription[what].Description
}

func (what RiskExploitationImpact) Title() string {
	return [...]string{"Low", "Medium", "High", "Very High"}[what]
}

func (what RiskExploitationImpact) Weight() int {
	return [...]int{1, 2, 3, 4}[what]
}

func (what RiskExploitationImpact) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}
