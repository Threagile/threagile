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

type Authentication int

const (
	NoneAuthentication Authentication = iota
	Credentials
	SessionId
	Token
	ClientCertificate
	TwoFactor
	Externalized
)

func AuthenticationValues() []TypeEnum {
	return []TypeEnum{
		NoneAuthentication,
		Credentials,
		SessionId,
		Token,
		ClientCertificate,
		TwoFactor,
		Externalized,
	}
}

var AuthenticationTypeDescription = [...]TypeDescription{
	{"none", "No authentication"},
	{"credentials", "Username and password, pin or passphrase"},
	{"session-id", "A server generated session id with limited life span"},
	{"token", "A server generated token. Containing session id, other data and is cryptographically signed"},
	{"client-certificate", "A certificate file stored on the client identifying this specific client"},
	{"two-factor", "Credentials plus another factor like a physical object (card) or biometrics"},
	{"externalized", "Some external company handles authentication"},
}

func ParseAuthentication(value string) (authentication Authentication, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range AuthenticationValues() {
		if candidate.String() == value {
			return candidate.(Authentication), err
		}
	}
	return authentication, fmt.Errorf("unable to parse into type: %v", value)
}

func (what Authentication) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	//return [...]string{"none", "credentials", "session-id", "token", "client-certificate", "two-factor", "externalized"}[what]
	return AuthenticationTypeDescription[what].Name
}

func (what Authentication) Explain() string {
	return AuthenticationTypeDescription[what].Description
}

func (what Authentication) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *Authentication) UnmarshalJSON(data []byte) error {
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

func (what Authentication) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *Authentication) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what Authentication) find(value string) (Authentication, error) {
	for index, description := range AuthenticationTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return Authentication(index), nil
		}
	}

	return Authentication(0), fmt.Errorf("unknown authentication value %q", value)
}
