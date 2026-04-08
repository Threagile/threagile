package statements

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestAssignStatement_ParseMapSucceeds(t *testing.T) {
	stmt := new(AssignStatement)
	result, errScript, err := stmt.Parse(map[string]any{"x": "hello"})
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
}

func TestAssignStatement_ParseArrayOfMapsSucceeds(t *testing.T) {
	stmt := new(AssignStatement)
	result, errScript, err := stmt.Parse([]any{
		map[string]any{"x": "hello"},
		map[string]any{"y": "world"},
	})
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
}

func TestAssignStatement_ParseInvalidTypeReturnsError(t *testing.T) {
	stmt := new(AssignStatement)
	_, errScript, err := stmt.Parse(42)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected assign-statement format")
	assert.Equal(t, 42, errScript)
}

func TestAssignStatement_RunAssignsVariableToScope(t *testing.T) {
	stmt := new(AssignStatement)
	_, _, err := stmt.Parse(map[string]any{"x": "hello"})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	val, ok := scope.Get("x")
	assert.True(t, ok)
	assert.Equal(t, "hello", val.Value())
}

func TestAssignStatement_RunWhenHasReturnedIsNoop(t *testing.T) {
	stmt := new(AssignStatement)
	_, _, err := stmt.Parse(map[string]any{"x": "hello"})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)
	scope.HasReturned = true

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	_, ok := scope.Get("x")
	assert.False(t, ok)
}
