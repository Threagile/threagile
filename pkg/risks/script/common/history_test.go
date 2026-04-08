package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHistory(t *testing.T) {
	event := NewEvent(NewTrueProperty(), NewPath("a"))
	h := NewHistory(event)

	assert.Len(t, h, 1)
	assert.Same(t, event, h[0])
}

func TestHistory_New_Prepends(t *testing.T) {
	first := NewEvent(NewTrueProperty(), NewPath("first"))
	second := NewEvent(NewFalseProperty(), NewPath("second"))

	h := NewHistory(first)
	h2 := h.New(second)

	assert.Len(t, h2, 2)
	assert.Same(t, second, h2[0])
	assert.Same(t, first, h2[1])
}

func TestHistory_New_Nil(t *testing.T) {
	first := NewEvent(NewTrueProperty(), NewPath("first"))
	h := NewHistory(first)
	h2 := h.New(nil)

	assert.Len(t, h2, 1)
	assert.Same(t, first, h2[0])
}

func TestHistory_String(t *testing.T) {
	event := NewEvent(NewTrueProperty(), NewPath("item"))
	h := NewHistory(event)
	s := h.String()
	assert.Contains(t, s, "item")
	assert.Contains(t, s, "true")
}

func TestHistory_String_Empty(t *testing.T) {
	var h History
	assert.Equal(t, "", h.String())
}
