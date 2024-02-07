/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"strings"
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
	value = strings.TrimSpace(value)
	if value == "" {
		return MediumSeverity, nil
	}
	for _, candidate := range RiskSeverityValues() {
		if candidate.String() == value {
			return candidate.(RiskSeverity), err
		}
	}
	return riskSeverity, fmt.Errorf("unable to parse into type: %v", value)
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

func (what RiskSeverity) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *RiskSeverity) UnmarshalJSON(data []byte) error {
	var text string
	unmarshalError := json.Unmarshal(data, &text)
	if unmarshalError != nil {
		return unmarshalError
	}

	value, findError := what.find(text)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what RiskSeverity) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *RiskSeverity) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what RiskSeverity) find(value string) (RiskSeverity, error) {
	for index, description := range RiskSeverityTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return RiskSeverity(index), nil
		}
	}

	return RiskSeverity(0), fmt.Errorf("unknown risk severity value %q", value)
}
