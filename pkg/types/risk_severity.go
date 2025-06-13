/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
)

type RiskSeverity int

const (
	LowSeverity RiskSeverity = iota
	MediumSeverity
	ElevatedSeverity
	HighSeverity
	CriticalSeverity
)

func RiskSeverityValues() []TypeEnum {
	return []TypeEnum{
		LowSeverity,
		MediumSeverity,
		ElevatedSeverity,
		HighSeverity,
		CriticalSeverity,
	}
}

var RiskSeverityTypeDescription = [...]TypeDescription{
	{"low", "Low"},
	{"medium", "Medium"},
	{"elevated", "Elevated"},
	{"high", "High"},
	{"critical", "Critical"},
}

func ParseRiskSeverity(value string) (riskSeverity RiskSeverity, err error) {
	return RiskSeverity(0).Find(value)
}

func (what RiskSeverity) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return RiskSeverityTypeDescription[what].Name
}

func (what RiskSeverity) Explain() string {
	return RiskSeverityTypeDescription[what].Description
}

func (what RiskSeverity) Title() string {
	return [...]string{"Low", "Medium", "Elevated", "High", "Critical"}[what]
}

func (what RiskSeverity) Find(value string) (RiskSeverity, error) {
	if len(value) == 0 {
		return MediumSeverity, nil
	}

	for index, description := range RiskSeverityTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return RiskSeverity(index), nil
		}
	}

	return RiskSeverity(0), fmt.Errorf("unknown risk severity value %q", value)
}

func (what RiskSeverity) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *RiskSeverity) UnmarshalJSON(data []byte) error {
	var text string
	unmarshalError := json.Unmarshal(data, &text)
	if unmarshalError != nil {
		return unmarshalError
	}

	value, findError := what.Find(text)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func init() {
	yaml.RegisterCustomMarshaler[RiskSeverity](func(what RiskSeverity) ([]byte, error) {
		return []byte(what.String()), nil
	})

	yaml.RegisterCustomUnmarshaler[RiskSeverity](func(what *RiskSeverity, data []byte) error {
		value, findError := what.Find(strings.TrimSpace(string(data)))
		if findError != nil {
			return findError
		}

		*what = value
		return nil
	})
}
