package statements

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatement_ParseAssign(t *testing.T) {
	stmt := new(Statement)
	result, _, err := stmt.Parse("assign", map[string]any{"x": "hello"})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	_, ok := result.(*AssignStatement)
	assert.True(t, ok, "expected *AssignStatement, got %T", result)
}

func TestStatement_ParseReturn(t *testing.T) {
	stmt := new(Statement)
	result, _, err := stmt.Parse("return", "hello")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	_, ok := result.(*ReturnStatement)
	assert.True(t, ok, "expected *ReturnStatement, got %T", result)
}

func TestStatement_ParseIf(t *testing.T) {
	stmt := new(Statement)
	result, _, err := stmt.Parse("if", map[string]any{
		"equal": map[string]any{
			"first":  true,
			"second": true,
		},
		"then": map[string]any{
			"assign": map[string]any{"x": "yes"},
		},
	})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	_, ok := result.(*IfStatement)
	assert.True(t, ok, "expected *IfStatement, got %T", result)
}

func TestStatement_ParseLoop(t *testing.T) {
	stmt := new(Statement)
	result, _, err := stmt.Parse("loop", map[string]any{
		"in":   "my_list",
		"item": "elem",
		"do": map[string]any{
			"assign": map[string]any{"last": "elem"},
		},
	})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	_, ok := result.(*LoopStatement)
	assert.True(t, ok, "expected *LoopStatement, got %T", result)
}

func TestStatement_ParseDefer(t *testing.T) {
	stmt := new(Statement)
	result, _, err := stmt.Parse("defer", []any{
		map[string]any{"explain": "deferred"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	_, ok := result.(*DeferStatement)
	assert.True(t, ok, "expected *DeferStatement, got %T", result)
}

func TestStatement_ParseExplain(t *testing.T) {
	stmt := new(Statement)
	result, _, err := stmt.Parse("explain", "some explanation")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	_, ok := result.(*ExplainStatement)
	assert.True(t, ok, "expected *ExplainStatement, got %T", result)
}

func TestStatement_ParseUnknownReturnsError(t *testing.T) {
	stmt := new(Statement)
	_, _, err := stmt.Parse("unknown", "body")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected keyword")
	assert.Contains(t, err.Error(), "unknown")
}
