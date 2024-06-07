package common

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

func ToLiteral(script any) string {
	switch script.(type) {
	case []any, map[string]any:
		data, marshalError := yaml.Marshal(script)
		if marshalError != nil {
			return fmt.Sprintf("%v", script)
		}

		return string(data)

	default:
		return fmt.Sprintf("%v", script)
	}
}
