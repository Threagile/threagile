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

type RiskStatus int

const (
	Unchecked RiskStatus = iota
	InDiscussion
	Accepted
	InProgress
	Mitigated
	FalsePositive
)

func RiskStatusValues() []TypeEnum {
	return []TypeEnum{
		Unchecked,
		InDiscussion,
		Accepted,
		InProgress,
		Mitigated,
		FalsePositive,
	}
}

var RiskStatusTypeDescription = [...]TypeDescription{
	{"unchecked", "Risk has not yet been reviewed"},
	{"in-discussion", "Risk is currently being discussed (during review)"},
	{"accepted", "Risk has been accepted (as possibly a corporate risk acceptance process defines)"},
	{"in-progress", "Risk mitigation is currently in progress"},
	{"mitigated", "Risk has been mitigated"},
	{"false-positive", "Risk is a false positive (i.e. no risk at all or not applicable)"},
}

func ParseRiskStatus(value string) (riskStatus RiskStatus, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range RiskStatusValues() {
		if candidate.String() == value {
			return candidate.(RiskStatus), err
		}
	}
	return riskStatus, errors.New("Unable to parse into type: " + value)
}

func (what RiskStatus) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return RiskStatusTypeDescription[what].Name
}

func (what RiskStatus) Explain() string {
	return RiskStatusTypeDescription[what].Description
}

func (what RiskStatus) Title() string {
	return [...]string{"Unchecked", "in Discussion", "Accepted", "in Progress", "Mitigated", "False Positive"}[what]
}

func (what RiskStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what RiskStatus) IsStillAtRisk() bool {
	return what == Unchecked || what == InDiscussion || what == Accepted || what == InProgress
}

func (what *RiskStatus) UnmarshalJSON([]byte) error {
	for index, description := range RiskStatusTypeDescription {
		if strings.ToLower(what.String()) == strings.ToLower(description.Name) {
			*what = RiskStatus(index)
			return nil
		}
	}

	return fmt.Errorf("unknown risk status value %q", int(*what))
}
