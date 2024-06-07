/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type DataFormat int

const (
	JSON DataFormat = iota
	XML
	Serialization
	File
	CSV
	YAML
)

func DataFormatValues() []TypeEnum {
	return []TypeEnum{
		JSON,
		XML,
		Serialization,
		File,
		CSV,
		YAML,
	}
}

var DataFormatTypeDescription = [...]TypeDescription{
	{"json", "JSON"},
	{"xml", "XML"},
	{"serialization", "Serialized program objects"},
	{"file", "Specific file types for data"},
	{"csv", "CSV"},
	{"yaml", "YAML"},
}

func ParseDataFormat(value string) (dataFormat DataFormat, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range DataFormatValues() {
		if candidate.String() == value {
			return candidate.(DataFormat), err
		}
	}
	return dataFormat, fmt.Errorf("unable to parse into type: %v", value)
}

func (what DataFormat) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return DataFormatTypeDescription[what].Name
}

func (what DataFormat) Explain() string {
	return DataFormatTypeDescription[what].Description
}

func (what DataFormat) Title() string {
	return [...]string{"JSON", "XML", "Serialization", "File", "CSV", "YAML"}[what]
}

func (what DataFormat) Description() string {
	return [...]string{"JSON marshalled object data", "XML structured data", "Serialization-based object graphs",
		"File input/uploads", "CSV tabular data", "YAML structured configuration format"}[what]
}

type ByDataFormatAcceptedSort []DataFormat

func (what ByDataFormatAcceptedSort) Len() int      { return len(what) }
func (what ByDataFormatAcceptedSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByDataFormatAcceptedSort) Less(i, j int) bool {
	return what[i].String() < what[j].String()
}

func (what DataFormat) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *DataFormat) UnmarshalJSON(data []byte) error {
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

func (what DataFormat) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *DataFormat) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what DataFormat) find(value string) (DataFormat, error) {
	for index, description := range DataFormatTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return DataFormat(index), nil
		}
	}

	return DataFormat(0), fmt.Errorf("unknown data format value %q", value)
}
