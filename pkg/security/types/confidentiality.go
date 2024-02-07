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

type Confidentiality int

const (
	Public Confidentiality = iota
	Internal
	Restricted
	Confidential
	StrictlyConfidential
)

func ConfidentialityValues() []TypeEnum {
	return []TypeEnum{
		Public,
		Internal,
		Restricted,
		Confidential,
		StrictlyConfidential,
	}
}

func ParseConfidentiality(value string) (confidentiality Confidentiality, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range ConfidentialityValues() {
		if candidate.String() == value {
			return candidate.(Confidentiality), err
		}
	}
	return confidentiality, fmt.Errorf("unable to parse into type: %v", value)
}

var ConfidentialityTypeDescription = [...]TypeDescription{
	{"public", "Public available information"},
	{"internal", "(Company) internal information - but all people in the institution can access it"},
	{"restricted", "Internal and with restricted access"},
	{"confidential", "Only a few selected people have access"},
	{"strictly-confidential", "Highest secrecy level"},
}

func (what Confidentiality) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return ConfidentialityTypeDescription[what].Name
}

func (what Confidentiality) Explain() string {
	return ConfidentialityTypeDescription[what].Description
}

func (what Confidentiality) AttackerAttractivenessForAsset() float64 {
	// fibonacci starting at 8
	return [...]float64{8, 13, 21, 34, 55}[what]
}
func (what Confidentiality) AttackerAttractivenessForProcessedOrStoredData() float64 {
	// fibonacci starting at 5
	return [...]float64{5, 8, 13, 21, 34}[what]
}
func (what Confidentiality) AttackerAttractivenessForInOutTransferredData() float64 {
	// fibonacci starting at 2
	return [...]float64{2, 3, 5, 8, 13}[what]
}

func (what Confidentiality) RatingStringInScale() string {
	result := "(rated "
	if what == Public {
		result += "1"
	}
	if what == Internal {
		result += "2"
	}
	if what == Restricted {
		result += "3"
	}
	if what == Confidential {
		result += "4"
	}
	if what == StrictlyConfidential {
		result += "5"
	}
	result += " in scale of 5)"
	return result
}

func (what Confidentiality) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *Confidentiality) UnmarshalJSON(data []byte) error {
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

func (what Confidentiality) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *Confidentiality) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what Confidentiality) find(value string) (Confidentiality, error) {
	for index, description := range ConfidentialityTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return Confidentiality(index), nil
		}
	}

	return Confidentiality(0), fmt.Errorf("unknown confidentiality value %q", value)
}
