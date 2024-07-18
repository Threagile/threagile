package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExplainText(t *testing.T) {
	assert.Equal(t,
		"some text",
		NewExplain("some text").Text().String())
}

func TestExplainNegate(t *testing.T) {
	assert.Equal(t,
		"some text",
		NewExplain("some text").Negate().Text().String())
}
