/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
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
	return riskFunction, fmt.Errorf("unable to parse into type: %v", value)
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
	return []byte(what.String()), nil
}

func (what *RiskFunction) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))

	value, findError := what.find(text)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what RiskFunction) find(value string) (RiskFunction, error) {
	for index, description := range RiskFunctionTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return RiskFunction(index), nil
		}
	}

	return RiskFunction(0), fmt.Errorf("unknown risk function value %q", value)
}

func init() {
	yaml.RegisterCustomMarshaler[RiskFunction](func(what RiskFunction) ([]byte, error) {
		return []byte(what.String()), nil
	})

	yaml.RegisterCustomUnmarshaler[RiskFunction](func(what *RiskFunction, data []byte) error {
		value, findError := what.find(strings.TrimSpace(string(data)))
		if findError != nil {
			return findError
		}

		*what = value
		return nil
	})
}
