package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEvent(t *testing.T) {
	prop := NewBlankProperty()
	path := NewPath("a", "b")
	e := NewEvent(prop, path)

	assert.Same(t, prop, e.Property)
	assert.Same(t, path, e.Origin)
	assert.Nil(t, e.Events)
}

func TestNewEventFrom(t *testing.T) {
	prop := NewTrueProperty()
	firstVal := SomeStringValue("hello", NewEvent(NewBlankProperty(), NewPath("x")))
	secondVal := SomeStringValue("world", NewEvent(NewBlankProperty(), NewPath("y")))

	e := NewEventFrom(prop, firstVal, secondVal)

	assert.Same(t, prop, e.Property)
	assert.NotNil(t, e.Origin)
	assert.Equal(t, firstVal.Event().Path().Path, e.Origin.Path)
	assert.Contains(t, e.Events, secondVal.Event())
}

func TestNewEventFrom_NilFirstValue(t *testing.T) {
	prop := NewTrueProperty()
	secondVal := SomeStringValue("world", NewEvent(NewBlankProperty(), NewPath("y")))

	e := NewEventFrom(prop, nil, secondVal)

	assert.Same(t, prop, e.Property)
	assert.Nil(t, e.Origin)
}

func TestEmptyEvent(t *testing.T) {
	e := EmptyEvent()
	assert.NotNil(t, e)
	assert.NotNil(t, e.Property)
}

func TestEvent_From(t *testing.T) {
	e := EmptyEvent()
	val := SomeStringValue("v", NewEvent(NewBlankProperty(), NewPath("p")))
	result := e.From(val)

	assert.Same(t, e, result)
	assert.Len(t, e.Events, 1)
	assert.Same(t, val.Event(), e.Events[0])
}

func TestEvent_From_Nil(t *testing.T) {
	var e *Event
	assert.Nil(t, e.From())
}

func TestEvent_AddHistory(t *testing.T) {
	e := EmptyEvent()
	child := NewEvent(NewBlankProperty(), NewPath("c"))
	result := e.AddHistory([]*Event{child})

	assert.Same(t, e, result)
	assert.Contains(t, e.Events, child)
}

func TestEvent_AddHistory_Nil(t *testing.T) {
	var e *Event
	assert.Nil(t, e.AddHistory(nil))
}

func TestEvent_Path(t *testing.T) {
	path := NewPath("a")
	e := NewEvent(NewBlankProperty(), path)
	assert.Same(t, path, e.Path())
}

func TestEvent_Path_Nil(t *testing.T) {
	var e *Event
	assert.Nil(t, e.Path())
}

func TestEvent_SetPath(t *testing.T) {
	e := EmptyEvent()
	path := NewPath("new")
	result := e.SetPath(path)

	assert.Same(t, e, result)
	assert.Same(t, path, e.Origin)
}

func TestEvent_SetPath_Nil(t *testing.T) {
	var e *Event
	assert.Nil(t, e.SetPath(NewPath("x")))
}

func TestEvent_String_Nil(t *testing.T) {
	var e *Event
	assert.Equal(t, "", e.String())
}

func TestEvent_String_NonNil(t *testing.T) {
	e := NewEvent(NewTrueProperty(), NewPath("item"))
	s := e.String()
	assert.Contains(t, s, "item")
	assert.Contains(t, s, "true")
}

func TestEvent_Indented_Nil(t *testing.T) {
	var e *Event
	assert.Equal(t, []string{}, e.Indented(0))
}

func TestEvent_Indented_WithEvents(t *testing.T) {
	parent := NewEvent(NewTrueProperty(), NewPath("root"))
	child := NewEvent(NewFalseProperty(), NewPath("leaf"))
	parent.Events = append(parent.Events, child)

	lines := parent.Indented(0)
	assert.NotEmpty(t, lines)
	assert.Contains(t, lines[0], "because")
}
