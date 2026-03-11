package statements

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestStatementList_ParseSingleElementMapDelegatesToStatement(t *testing.T) {
	sl := new(StatementList)
	result, errScript, err := sl.Parse(map[string]any{
		"assign": map[string]any{"x": "hello"},
	})
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
	_, isAssign := result.(*AssignStatement)
	assert.True(t, isAssign, "expected *AssignStatement, got %T", result)
}

func TestStatementList_ParseArrayWithMultipleMapsCreatesList(t *testing.T) {
	sl := new(StatementList)
	result, errScript, err := sl.Parse([]any{
		map[string]any{"assign": map[string]any{"x": "hello"}},
		map[string]any{"assign": map[string]any{"y": "world"}},
	})
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
	_, isList := result.(*StatementList)
	assert.True(t, isList, "expected *StatementList, got %T", result)
}

func TestStatementList_ParseSingleElementArrayUnwraps(t *testing.T) {
	sl := new(StatementList)
	result, _, err := sl.Parse([]any{
		map[string]any{"assign": map[string]any{"x": "hello"}},
	})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	_, isAssign := result.(*AssignStatement)
	assert.True(t, isAssign, "expected single element to be unwrapped to *AssignStatement, got %T", result)
}

func TestStatementList_RunExecutesAllStatements(t *testing.T) {
	sl := new(StatementList)
	result, _, err := sl.Parse([]any{
		map[string]any{"assign": map[string]any{"x": "hello"}},
		map[string]any{"assign": map[string]any{"y": "world"}},
	})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	errLiteral, runErr := result.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	valX, okX := scope.Get("x")
	assert.True(t, okX)
	assert.Equal(t, "hello", valX.Value())

	valY, okY := scope.Get("y")
	assert.True(t, okY)
	assert.Equal(t, "world", valY.Value())
}

func TestStatementList_RunStopsWhenHasReturnedBecomesTrue(t *testing.T) {
	sl := new(StatementList)
	result, _, err := sl.Parse([]any{
		map[string]any{"return": "early"},
		map[string]any{"assign": map[string]any{"x": "should-not-run"}},
	})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	errLiteral, runErr := result.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	assert.True(t, scope.HasReturned)

	_, ok := scope.Get("x")
	assert.False(t, ok)
}

func TestStatementList_RunWhenHasReturnedIsNoop(t *testing.T) {
	sl := new(StatementList)
	result, _, err := sl.Parse([]any{
		map[string]any{"assign": map[string]any{"x": "hello"}},
		map[string]any{"assign": map[string]any{"y": "world"}},
	})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)
	scope.HasReturned = true

	errLiteral, runErr := result.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	_, okX := scope.Get("x")
	assert.False(t, okX)
	_, okY := scope.Get("y")
	assert.False(t, okY)
}
