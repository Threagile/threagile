package common

import (
	"fmt"

	"github.com/goccy/go-yaml"
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
