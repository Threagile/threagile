package common

import (
	"github.com/threagile/threagile/pkg/input"
	"gopkg.in/yaml.v3"
)

type RiskTemplate struct {
	input.RiskIdentified
	ID    string `yaml:"id"`
	Title string `yaml:"title"`
}

func (what *RiskTemplate) Parse(value any) (*RiskTemplate, any, error) {
	data, marshalError := yaml.Marshal(value)
	if marshalError != nil {
		return nil, value, marshalError
	}

	unmarshalError := yaml.Unmarshal(data, what)
	if unmarshalError != nil {
		return nil, string(data), marshalError
	}

	unmarshalEmbeddedError := yaml.Unmarshal(data, &what.RiskIdentified)
	if unmarshalEmbeddedError != nil {
		return nil, string(data), unmarshalEmbeddedError
	}

	return what, nil, nil
}
