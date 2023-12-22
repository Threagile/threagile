/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package types

import "encoding/json"

type RiskFunction int

const (
	BusinessSide RiskFunction = iota
	Architecture
	Development
	Operations
)

func RiskFunctionValues() []TypeEnum {
	return []TypeEnum{
		BusinessSide,
		Architecture,
		Development,
		Operations,
	}
}

var RiskFunctionTypeDescription = [...]TypeDescription{
	{"business-side", "Business"},
	{"architecture", "Architecture"},
	{"development", "Development"},
	{"operations", "Operations"},
}

func (what RiskFunction) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return RiskFunctionTypeDescription[what].Name
}

func (what RiskFunction) Explain() string {
	return RiskFunctionTypeDescription[what].Description
}

func (what RiskFunction) Title() string {
	return [...]string{"Business Side", "Architecture", "Development", "Operations"}[what]
}

func (what RiskFunction) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}
