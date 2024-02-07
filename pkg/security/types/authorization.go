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

type Authorization int

const (
	NoneAuthorization Authorization = iota
	TechnicalUser
	EndUserIdentityPropagation
)

func AuthorizationValues() []TypeEnum {
	return []TypeEnum{
		NoneAuthorization,
		TechnicalUser,
		EndUserIdentityPropagation,
	}
}

var AuthorizationTypeDescription = [...]TypeDescription{
	{"none", "No authorization"},
	{"technical-user", "Technical user (service-to-service) like DB user credentials"},
	{"enduser-identity-propagation", "Identity of end user propagates to this service"},
}

func ParseAuthorization(value string) (authorization Authorization, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range AuthorizationValues() {
		if candidate.String() == value {
			return candidate.(Authorization), err
		}
	}
	return authorization, fmt.Errorf("unable to parse into type: %v", value)
}

func (what Authorization) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return AuthorizationTypeDescription[what].Name
}

func (what Authorization) Explain() string {
	return AuthorizationTypeDescription[what].Description
}

func (what Authorization) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *Authorization) UnmarshalJSON(data []byte) error {
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

func (what Authorization) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *Authorization) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what Authorization) find(value string) (Authorization, error) {
	for index, description := range AuthorizationTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return Authorization(index), nil
		}
	}

	return Authorization(0), fmt.Errorf("unknown authorization value %q", value)
}
