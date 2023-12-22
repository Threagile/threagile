/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package types

import (
	"errors"
	"strings"
)

type Criticality int

const (
	Archive Criticality = iota
	Operational
	Important
	Critical
	MissionCritical
)

func CriticalityValues() []TypeEnum {
	return []TypeEnum{
		Archive,
		Operational,
		Important,
		Critical,
		MissionCritical,
	}
}

func ParseCriticality(value string) (criticality Criticality, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range CriticalityValues() {
		if candidate.String() == value {
			return candidate.(Criticality), err
		}
	}
	return criticality, errors.New("Unable to parse into type: " + value)
}

var CriticalityTypeDescription = [...]TypeDescription{
	{"archive", "Stored, not active"},
	{"operational", "If this fails, people will just have an ad-hoc coffee break until it is back"},
	{"important", "Issues here results in angry people"},
	{"critical", "Failure is really expensive or crippling"},
	{"mission-critical", "This must not fail"},
}

func (what Criticality) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return CriticalityTypeDescription[what].Name
}

func (what Criticality) Explain() string {
	return CriticalityTypeDescription[what].Description
}

func (what Criticality) AttackerAttractivenessForAsset() float64 {
	// fibonacci starting at 5
	return [...]float64{5, 8, 13, 21, 34}[what]
}
func (what Criticality) AttackerAttractivenessForProcessedOrStoredData() float64 {
	// fibonacci starting at 3
	return [...]float64{3, 5, 8, 13, 21}[what]
}
func (what Criticality) AttackerAttractivenessForInOutTransferredData() float64 {
	// fibonacci starting at 2
	return [...]float64{2, 3, 5, 8, 13}[what]
}

func (what Criticality) RatingStringInScale() string {
	result := "(rated "
	if what == Archive {
		result += "1"
	}
	if what == Operational {
		result += "2"
	}
	if what == Important {
		result += "3"
	}
	if what == Critical {
		result += "4"
	}
	if what == MissionCritical {
		result += "5"
	}
	result += " in scale of 5)"
	return result
}
