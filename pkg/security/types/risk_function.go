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

func ParseRiskFunction(value string) (riskFunction RiskFunction, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range RiskFunctionValues() {
		if candidate.String() == value {
			return candidate.(RiskFunction), err
		}
	}
	return riskFunction, errors.New("Unable to parse into type: " + value)
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

func (what *RiskFunction) UnmarshalJSON([]byte) error {
	for index, description := range RiskFunctionTypeDescription {
		if strings.ToLower(what.String()) == strings.ToLower(description.Name) {
			*what = RiskFunction(index)
			return nil
		}
	}

	return fmt.Errorf("unknown risk function %q", int(*what))
}
