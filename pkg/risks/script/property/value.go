package property

import (
	"fmt"
)

type Value struct {
	value   any
	negated bool
}

func NewValue(value any) *Value {
	return &Value{value: value}
}

func (what *Value) Negate() {
	what.negated = !what.negated
}

func (what *Value) Negated() bool {
	return what.negated
}

func (what *Value) Text() []string {
	text := make([]string, 0)
	switch castValue := what.value.(type) {
	case Texter:
		if what.negated {
			text = append(text, "not")
		}

		for _, value := range castValue.Text() {
			text = append(text, fmt.Sprintf("  %v", value))
		}

	case []any:
		if what.negated {
			text = append(text, "not")
		}

		for _, item := range castValue {
			text = append(text, fmt.Sprintf("  - %v", item))
		}

	case map[string]any:
		if what.negated {
			text = append(text, "not")
		}

		for name, item := range castValue {
			text = append(text, fmt.Sprintf("  %v: %v", name, item))
		}

	default:
		if what.negated {
			text = append(text, fmt.Sprintf("not %v", castValue))
		} else {
			text = append(text, fmt.Sprintf("%v", castValue))
		}
	}

	return text
}
