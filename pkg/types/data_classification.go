package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type DataClassification int

const (
	PublicData DataClassification = iota
	InternalUseData
	ConfidentialData
	RetrictedData
	NoDataStored
)

func DataClassificationValues() []TypeEnum {
	return []TypeEnum{
		PublicData,
		InternalUseData,
		ConfidentialData,
		RetrictedData,
		NoDataStored,
	}
}

func ParseDataClassification(value string) (dataClassification DataClassification, err error) {
	return DataClassification(0).Find(value)
}

var DataClassificationTypeDescription = [...]TypeDescription{
	{"public", "Stored, not active"},
	{"internal-use", "If this fails, people will just have an ad-hoc coffee break until it is back"},
	{"confidential", "Issues here results in angry people"},
	{"restricted", "Failure is really expensive or crippling"},
	{"no-data-stored", "This must not fail"},
}

func (what DataClassification) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return DataClassificationTypeDescription[what].Name
}

func (what DataClassification) Explain() string {
	return DataClassificationTypeDescription[what].Description
}

func (what DataClassification) AttackerAttractivenessForAsset() float64 {
	// fibonacci starting at 1
	return [...]float64{1, 2, 3, 5, 8}[what]
}
func (what DataClassification) AttackerAttractivenessForProcessedOrStoredData() float64 {
	// fibonacci starting at 1
	return [...]float64{1, 2, 3, 5, 8}[what]
}
func (what DataClassification) AttackerAttractivenessForInOutTransferredData() float64 {
	// fibonacci starting at 1
	return [...]float64{1, 2, 3, 5, 8}[what]
}

func (what DataClassification) RatingStringInScale() string {
	result := "(rated "
	if what == NoDataStored {
		result += "1"
	}
	if what == PublicData {
		result += "2"
	}
	if what == InternalUseData {
		result += "3"
	}
	if what == ConfidentialData {
		result += "4"
	}
	if what == RetrictedData {
		result += "5"
	}

	result += " in scale of 5)"
	return result
}

func (what DataClassification) Find(value string) (DataClassification, error) {
	for index, description := range DataClassificationTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return DataClassification(index), nil
		}
	}

	return DataClassification(0), fmt.Errorf("unknown DataClassification value %q", value)
}

func (what DataClassification) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *DataClassification) UnmarshalJSON(data []byte) error {
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

func (what DataClassification) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *DataClassification) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.Find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}
