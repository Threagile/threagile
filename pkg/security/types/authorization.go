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
	return authorization, errors.New("Unable to parse into type: " + value)
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

func (what *Authorization) UnmarshalJSON([]byte) error {
	for index, description := range AuthorizationTypeDescription {
		if strings.ToLower(what.String()) == strings.ToLower(description.Name) {
			*what = Authorization(index)
			return nil
		}
	}

	return fmt.Errorf("unknown authorization value %q", int(*what))
}