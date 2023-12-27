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
	return authentication, errors.New("Unable to parse into type: " + value)
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

func (what *Authentication) UnmarshalJSON([]byte) error {
	for index, description := range AuthenticationTypeDescription {
		if strings.ToLower(what.String()) == strings.ToLower(description.Name) {
			*what = Authentication(index)
			return nil
		}
	}

	return fmt.Errorf("unknown authentication value %q", int(*what))
}