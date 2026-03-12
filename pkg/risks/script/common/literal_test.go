package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToLiteral_Map(t *testing.T) {
	input := map[string]any{"key": "value"}
	result := ToLiteral(input)
	assert.Contains(t, result, "key:")
	assert.Contains(t, result, "value")
}

func TestToLiteral_Slice(t *testing.T) {
	input := []any{"a", "b"}
	result := ToLiteral(input)
	assert.Contains(t, result, "- a")
	assert.Contains(t, result, "- b")
}

func TestToLiteral_String(t *testing.T) {
	result := ToLiteral("hello")
	assert.Equal(t, "hello", result)
}

func TestToLiteral_Int(t *testing.T) {
	result := ToLiteral(42)
	assert.Equal(t, "42", result)
}
