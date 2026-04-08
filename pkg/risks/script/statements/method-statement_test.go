package statements

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestMethodStatement_ParseWithParameterAndDoSucceeds(t *testing.T) {
	stmt := new(MethodStatement)
	result, errScript, err := stmt.Parse(map[string]any{
		"parameter": "x",
		"do": map[string]any{
			"assign": map[string]any{"result": "x"},
		},
	})
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
}

func TestMethodStatement_ParseWithParametersListSucceeds(t *testing.T) {
	stmt := new(MethodStatement)
	result, errScript, err := stmt.Parse(map[string]any{
		"parameters": []any{"x", "y"},
		"do": map[string]any{
			"assign": map[string]any{"result": "x"},
		},
	})
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
}

func TestMethodStatement_ParseWithUnexpectedKeyReturnsError(t *testing.T) {
	stmt := new(MethodStatement)
	_, _, err := stmt.Parse(map[string]any{
		"parameter": "x",
		"unknown":   "bad",
		"do": map[string]any{
			"assign": map[string]any{"result": "x"},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected statement")
}

func TestMethodStatement_RunBindsArgsAndExecutesBody(t *testing.T) {
	stmt := new(MethodStatement)
	_, _, err := stmt.Parse(map[string]any{
		"parameter": "x",
		"do": map[string]any{
			"assign": map[string]any{"result": "{x}"},
		},
	})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)
	scope.Args = []common.Value{common.SomeStringValue("hello", nil)}

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	val, ok := scope.Get("result")
	assert.True(t, ok)
	assert.Equal(t, "hello", val.Value())
}

func TestMethodStatement_RunWithWrongNumberOfArgsReturnsError(t *testing.T) {
	stmt := new(MethodStatement)
	_, _, err := stmt.Parse(map[string]any{
		"parameters": []any{"x", "y"},
		"do": map[string]any{
			"assign": map[string]any{"result": "x"},
		},
	})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)
	scope.Args = []common.Value{common.SomeStringValue("hello", nil)}

	_, runErr := stmt.Run(scope)
	assert.Error(t, runErr)
	assert.Contains(t, runErr.Error(), "expected 2 parameters, got 1")
}

func TestMethodStatement_RunWhenHasReturnedIsNoop(t *testing.T) {
	stmt := new(MethodStatement)
	_, _, err := stmt.Parse(map[string]any{
		"parameter": "x",
		"do": map[string]any{
			"assign": map[string]any{"result": "x"},
		},
	})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)
	scope.HasReturned = true
	scope.Args = []common.Value{common.SomeStringValue("hello", nil)}

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	_, ok := scope.Get("result")
	assert.False(t, ok)
}
