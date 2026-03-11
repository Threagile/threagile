package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewBlankProperty(t *testing.T) {
	p := NewBlankProperty()
	assert.NotNil(t, p)
	assert.Empty(t, p.Text())
}

func TestNewEqualProperty_WithEvent(t *testing.T) {
	event := NewEvent(NewBlankProperty(), NewPath("origin"))
	val := SomeStringValue("test", event)

	p := NewEqualProperty(val)
	assert.NotNil(t, p)
	assert.NotNil(t, p.Path)
	assert.Equal(t, event.Path().Path, p.Path.Path)
}

func TestNewTrueProperty(t *testing.T) {
	p := NewTrueProperty()
	assert.NotNil(t, p)

	text := p.Text()
	assert.Len(t, text, 1)
	assert.Equal(t, "true", text[0])
}

func TestNewFalseProperty(t *testing.T) {
	p := NewFalseProperty()
	assert.NotNil(t, p)

	text := p.Text()
	assert.Len(t, text, 1)
	assert.Equal(t, "false", text[0])
}

func TestProperty_Text_Nil(t *testing.T) {
	var p *Property
	assert.Equal(t, []string{}, p.Text())
}

func TestProperty_SetPath_Nil(t *testing.T) {
	var p *Property
	assert.Nil(t, p.SetPath(NewPath("x")))
}

func TestProperty_AddPathParent_Nil(t *testing.T) {
	var p *Property
	assert.Nil(t, p.AddPathParent("x"))
}

func TestProperty_AddPathLeaf_Nil(t *testing.T) {
	var p *Property
	assert.Nil(t, p.AddPathLeaf("x"))
}

func TestProperty_SetPath(t *testing.T) {
	p := NewTrueProperty()
	path := NewPath("new")
	result := p.SetPath(path)

	assert.Same(t, p, result)
	assert.Same(t, path, p.Path)
}

func TestProperty_AddPathParent(t *testing.T) {
	p := NewTrueProperty()
	p.Path = NewPath("child")
	p.AddPathParent("parent")

	assert.Equal(t, []string{"parent", "child"}, p.Path.Path)
}

func TestProperty_AddPathLeaf(t *testing.T) {
	p := NewTrueProperty()
	p.Path = NewPath("parent")
	p.AddPathLeaf("child")

	assert.Equal(t, []string{"parent", "child"}, p.Path.Path)
}
