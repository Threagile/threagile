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
	return riskSeverity, errors.New("Unable to parse into type: " + value)
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

func (what *RiskSeverity) UnmarshalJSON([]byte) error {
	for index, description := range RiskSeverityTypeDescription {
		if strings.ToLower(what.String()) == strings.ToLower(description.Name) {
			*what = RiskSeverity(index)
			return nil
		}
	}

	return fmt.Errorf("unknown risk severity value %q", int(*what))
}
