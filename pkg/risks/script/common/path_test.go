package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPath(t *testing.T) {
	p := NewPath("a", "b")
	assert.Equal(t, []string{"a", "b"}, p.Path)
}

func TestEmptyPath(t *testing.T) {
	p := EmptyPath()
	assert.NotNil(t, p)
	assert.Empty(t, p.Path)
}

func TestPath_Copy(t *testing.T) {
	p := NewPath("a", "b")
	c := p.Copy()

	assert.Equal(t, p.Path, c.Path)
	assert.NotSame(t, p, c)
}

func TestPath_Copy_IndependentOnAppend(t *testing.T) {
	p := NewPath("a", "b")
	c := p.Copy()

	// Appending to the copy does not affect the original
	c.AddPathLeaf("extra")
	assert.Len(t, p.Path, 2)
	assert.Len(t, c.Path, 3)
}

func TestPath_Copy_Nil(t *testing.T) {
	var p *Path
	assert.Nil(t, p.Copy())
}

func TestPath_SetPath(t *testing.T) {
	p := NewPath("a", "b")
	result := p.SetPath("x", "y", "z")
	assert.Equal(t, []string{"x", "y", "z"}, p.Path)
	assert.Same(t, p, result)
}

func TestPath_SetPath_Nil(t *testing.T) {
	var p *Path
	assert.Nil(t, p.SetPath("x"))
}

func TestPath_AddPathParent(t *testing.T) {
	p := NewPath("a", "b")
	result := p.AddPathParent("x")
	assert.Equal(t, []string{"x", "a", "b"}, p.Path)
	assert.Same(t, p, result)
}

func TestPath_AddPathParent_Nil(t *testing.T) {
	var p *Path
	assert.Nil(t, p.AddPathParent("x"))
}

func TestPath_AddPathLeaf(t *testing.T) {
	p := NewPath("a", "b")
	result := p.AddPathLeaf("x")
	assert.Equal(t, []string{"a", "b", "x"}, p.Path)
	assert.Same(t, p, result)
}

func TestPath_AddPathLeaf_Nil(t *testing.T) {
	var p *Path
	assert.Nil(t, p.AddPathLeaf("x"))
}

func TestPath_String_Reversed(t *testing.T) {
	p := NewPath("confidentiality", "data_asset", "model")
	assert.Equal(t, "model of data_asset of confidentiality", p.String())
}

func TestPath_String_Empty(t *testing.T) {
	p := EmptyPath()
	assert.Equal(t, "", p.String())
}

func TestPath_String_Nil(t *testing.T) {
	var p *Path
	assert.Equal(t, "", p.String())
}

func TestPath_String_SingleElement(t *testing.T) {
	p := NewPath("only")
	assert.Equal(t, "only", p.String())
}
