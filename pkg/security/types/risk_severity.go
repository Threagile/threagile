/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
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
