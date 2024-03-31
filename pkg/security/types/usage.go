/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"strings"
)

type Usage int

const (
	Business Usage = iota
	DevOps
)

func UsageValues() []TypeEnum {
	return []TypeEnum{
		Business,
		DevOps,
	}
}

func ParseUsage(value string) (usage Usage, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range UsageValues() {
		if candidate.String() == value {
			return candidate.(Usage), err
		}
	}
	return usage, fmt.Errorf("unable to parse into type: %v", value)
}

var UsageTypeDescription = [...]TypeDescription{
	{"business", "This system is operational and does business tasks"},
	{"devops", "This system is for development and/or deployment or other operational tasks"},
}

func (what Usage) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	//return [...]string{"business", "devops"}[what]
	return UsageTypeDescription[what].Name
}

func (what Usage) Explain() string {
	return UsageTypeDescription[what].Description
}

func (what Usage) Title() string {
	return [...]string{"Business", "DevOps"}[what]
}
