/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
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
	return EncryptionStyle(0).Find(value)
}

var EncryptionStyleTypeDescription = [...]TypeDescription{
	{"none", "No encryption"},
	{"transparent", "Encrypted data at rest"},
	{"data-with-symmetric-shared-key", "Both communication partners have the same key. This must be kept secret"},
	{"data-with-asymmetric-shared-key", "The key is split into public and private. Those two are shared between partners"},
	{"data-with-end-user-individual-key", "The key is (managed) by the end user"},
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

func (what EncryptionStyle) Find(value string) (EncryptionStyle, error) {
	for index, description := range EncryptionStyleTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return EncryptionStyle(index), nil
		}
	}

	return EncryptionStyle(0), fmt.Errorf("unknown encryption style value %q", value)
}

func (what EncryptionStyle) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *EncryptionStyle) UnmarshalJSON(data []byte) error {
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

func init() {
	yaml.RegisterCustomMarshaler[EncryptionStyle](func(what EncryptionStyle) ([]byte, error) {
		return []byte(what.String()), nil
	})

	yaml.RegisterCustomUnmarshaler[EncryptionStyle](func(what *EncryptionStyle, data []byte) error {
		value, findError := what.Find(strings.TrimSpace(string(data)))
		if findError != nil {
			return findError
		}

		*what = value
		return nil
	})
}
