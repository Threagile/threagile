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

type EncryptionStyle int

const (
	NoneEncryption EncryptionStyle = iota
	Transparent
	DataWithSymmetricSharedKey
	DataWithAsymmetricSharedKey
	DataWithEndUserIndividualKey
)

func EncryptionStyleValues() []TypeEnum {
	return []TypeEnum{
		NoneEncryption,
		Transparent,
		DataWithSymmetricSharedKey,
		DataWithAsymmetricSharedKey,
		DataWithEndUserIndividualKey,
	}
}

func ParseEncryptionStyle(value string) (encryptionStyle EncryptionStyle, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range EncryptionStyleValues() {
		if candidate.String() == value {
			return candidate.(EncryptionStyle), err
		}
	}
	return encryptionStyle, errors.New("Unable to parse into type: " + value)
}

var EncryptionStyleTypeDescription = [...]TypeDescription{
	{"none", "No encryption"},
	{"transparent", "Encrypted data at rest"},
	{"data-with-symmetric-shared-key", "Both communication partners have the same key. This must be kept secret"},
	{"data-with-asymmetric-shared-key", "The key is split into public and private. Those two are shared between partners"},
	{"data-with-enduser-individual-key", "The key is (managed) by the end user"},
}

func (what EncryptionStyle) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return EncryptionStyleTypeDescription[what].Name
}

func (what EncryptionStyle) Explain() string {
	return EncryptionStyleTypeDescription[what].Description
}

func (what EncryptionStyle) Title() string {
	return [...]string{"None", "Transparent", "Data with Symmetric Shared Key", "Data with Asymmetric Shared Key", "Data with End-User Individual Key"}[what]
}

func (what EncryptionStyle) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *EncryptionStyle) UnmarshalJSON([]byte) error {
	for index, description := range EncryptionStyleTypeDescription {
		if strings.ToLower(what.String()) == strings.ToLower(description.Name) {
			*what = EncryptionStyle(index)
			return nil
		}
	}

	return fmt.Errorf("unknown encryption style value %q", int(*what))
}
