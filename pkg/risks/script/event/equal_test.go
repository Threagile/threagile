package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEqualText(t *testing.T) {
	assert.Equal(t,
		"",
		NewEqual(
			NewTestValue("value1", nil),
			NewTestValue("value2", nil),
		).Text().String())

	assert.Equal(t,
		"value-path-1 is equal to value2",
		NewEqual(
			NewTestValue("value1", NewPath("value-path-1")),
			NewTestValue("value2", nil),
		).Text().String())

	assert.Equal(t,
		"value-path-1 is equal to value-path-2",
		NewEqual(
			NewTestValue("value1", NewPath("value-path-1")),
			NewTestValue("value2", NewPath("value-path-2")),
		).Text().String())
}

func TestEqualNegate(t *testing.T) {
	assert.Equal(t,
		"",
		NewEqual(
			NewTestValue("value1", nil),
			NewTestValue("value2", nil),
		).Negate().Text().String())

	assert.Equal(t,
		"value-path-1 is not equal to value2",
		NewEqual(
			NewTestValue("value1", NewPath("value-path-1")),
			NewTestValue("value2", nil),
		).Negate().Text().String())

	assert.Equal(t,
		"value-path-1 is not equal to value-path-2",
		NewEqual(
			NewTestValue("value1", NewPath("value-path-1")),
			NewTestValue("value2", NewPath("value-path-2")),
		).Negate().Text().String())
}
