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

func (what Usage) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *Usage) UnmarshalJSON(data []byte) error {
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

func (what Usage) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *Usage) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what Usage) find(value string) (Usage, error) {
	for index, description := range UsageTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return Usage(index), nil
		}
	}

	return Usage(0), fmt.Errorf("unknown usage type value %q", value)
}
