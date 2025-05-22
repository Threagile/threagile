package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type PersonalDataKind int

const (
	None PersonalDataKind = iota
	Unknown
	Personal
	NonPublic
	Sensitive
)

func PersonalDataKindValues() []TypeEnum {
	return []TypeEnum{
		None,
		Unknown,
		Personal,
		NonPublic,
		Sensitive,
	}
}

func ParsePersonalDataKind(value string) (dataClassification PersonalDataKind, err error) {
	return PersonalDataKind(0).Find(value)
}

var PersonalDataKindTypeDescription = [...]TypeDescription{
	{"none", "Stored, not active"},
	{"unknown", "If this fails, people will just have an ad-hoc coffee break until it is back"},
	{"personal", "Issues here results in angry people"},
	{"nonpublic", "Failure is really expensive or crippling"},
	{"sensitive", "This must not fail"},
}

func (what PersonalDataKind) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return PersonalDataKindTypeDescription[what].Name
}

func (what PersonalDataKind) Explain() string {
	return PersonalDataKindTypeDescription[what].Description
}

func (what PersonalDataKind) AttackerAttractivenessForAsset() float64 {
	// fibonacci starting at 1
	return [...]float64{1, 2, 3, 5, 8}[what]
}
func (what PersonalDataKind) AttackerAttractivenessForProcessedOrStoredData() float64 {
	// fibonacci starting at 1
	return [...]float64{1, 2, 3, 5, 8}[what]
}
func (what PersonalDataKind) AttackerAttractivenessForInOutTransferredData() float64 {
	// fibonacci starting at 1
	return [...]float64{1, 2, 3, 5, 8}[what]
}

func (what PersonalDataKind) RatingStringInScale() string {
	result := "(rated "
	if what == None {
		result += "1"
	}
	if what == Unknown {
		result += "2"
	}
	if what == Personal {
		result += "3"
	}
	if what == NonPublic {
		result += "4"
	}
	if what == Sensitive {
		result += "5"
	}

	result += " in scale of 5)"
	return result
}

func (what PersonalDataKind) Find(value string) (PersonalDataKind, error) {
	for index, description := range PersonalDataKindTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return PersonalDataKind(index), nil
		}
	}

	return PersonalDataKind(0), fmt.Errorf("unknown PersonalDataKind value %q", value)
}

func (what PersonalDataKind) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *PersonalDataKind) UnmarshalJSON(data []byte) error {
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

func (what PersonalDataKind) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *PersonalDataKind) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.Find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}
