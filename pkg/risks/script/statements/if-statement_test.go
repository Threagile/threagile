package statements

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestIfStatement_ParseWithThenElseSucceeds(t *testing.T) {
	stmt := new(IfStatement)
	result, errScript, err := stmt.Parse(map[string]any{
		"equal": map[string]any{
			"first":  true,
			"second": true,
		},
		"then": map[string]any{
			"assign": map[string]any{"result": "yes"},
		},
		"else": map[string]any{
			"assign": map[string]any{"result": "no"},
		},
	})
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
}

func TestIfStatement_RunTakesThenBranchWhenTrue(t *testing.T) {
	stmt := new(IfStatement)
	_, _, err := stmt.Parse(map[string]any{
		"equal": map[string]any{
			"first":  true,
			"second": true,
		},
		"then": map[string]any{
			"assign": map[string]any{"result": "yes"},
		},
		"else": map[string]any{
			"assign": map[string]any{"result": "no"},
		},
	})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	val, ok := scope.Get("result")
	assert.True(t, ok)
	assert.Equal(t, "yes", val.Value())
}

func TestIfStatement_RunTakesElseBranchWhenFalse(t *testing.T) {
	stmt := new(IfStatement)
	_, _, err := stmt.Parse(map[string]any{
		"equal": map[string]any{
			"first":  true,
			"second": false,
		},
		"then": map[string]any{
			"assign": map[string]any{"result": "yes"},
		},
		"else": map[string]any{
			"assign": map[string]any{"result": "no"},
		},
	})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	val, ok := scope.Get("result")
	assert.True(t, ok)
	assert.Equal(t, "no", val.Value())
}

func TestIfStatement_RunWithNoExpressionIsNoop(t *testing.T) {
	stmt := &IfStatement{}

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)
}

func TestIfStatement_RunWhenHasReturnedIsNoop(t *testing.T) {
	stmt := new(IfStatement)
	_, _, err := stmt.Parse(map[string]any{
		"equal": map[string]any{
			"first":  true,
			"second": true,
		},
		"then": map[string]any{
			"assign": map[string]any{"result": "yes"},
		},
	})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)
	scope.HasReturned = true

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	_, ok := scope.Get("result")
	assert.False(t, ok)
}

func TestIfStatement_RunWithNoElseBranchWhenFalseIsNoop(t *testing.T) {
	stmt := new(IfStatement)
	_, _, err := stmt.Parse(map[string]any{
		"equal": map[string]any{
			"first":  true,
			"second": false,
		},
		"then": map[string]any{
			"assign": map[string]any{"result": "yes"},
		},
	})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	_, ok := scope.Get("result")
	assert.False(t, ok)
}
