package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainText(t *testing.T) {
	assert.Equal(t,
		"",
		NewContain(
			NewTestValue("value1", nil),
			NewTestValue("value2", nil),
		).Text().String())

	assert.Equal(t,
		"value-path-1 contains value2",
		NewContain(
			NewTestValue("value1", NewPath("value-path-1")),
			NewTestValue("value2", nil),
		).Text().String())

	assert.Equal(t,
		"value-path-1 contains value-path-2",
		NewContain(
			NewTestValue("value1", NewPath("value-path-1")),
			NewTestValue("value2", NewPath("value-path-2")),
		).Text().String())
}

func TestContainNegate(t *testing.T) {
	assert.Equal(t,
		"",
		NewContain(
			NewTestValue("value1", nil),
			NewTestValue("value2", nil),
		).Negate().Text().String())

	assert.Equal(t,
		"value-path-1 does not contain value2",
		NewContain(
			NewTestValue("value1", NewPath("value-path-1")),
			NewTestValue("value2", nil),
		).Negate().Text().String())

	assert.Equal(t,
		"value-path-1 does not contain value-path-2",
		NewContain(
			NewTestValue("value1", NewPath("value-path-1")),
			NewTestValue("value2", NewPath("value-path-2")),
		).Negate().Text().String())
}
