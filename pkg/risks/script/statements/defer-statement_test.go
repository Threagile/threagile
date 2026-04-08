package statements

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestDeferStatement_ParseMapWithExplainSucceeds(t *testing.T) {
	stmt := new(DeferStatement)
	result, errScript, err := stmt.Parse(map[string]any{
		"explain": "some explanation",
	})
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
}

func TestDeferStatement_ParseArrayOfStatementsSucceeds(t *testing.T) {
	stmt := new(DeferStatement)
	result, errScript, err := stmt.Parse([]any{
		map[string]any{"explain": "first"},
		map[string]any{"explain": "second"},
	})
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
}

func TestDeferStatement_ParseInvalidTypeReturnsError(t *testing.T) {
	stmt := new(DeferStatement)
	_, errScript, err := stmt.Parse(42)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected defer-statement format")
	assert.Equal(t, 42, errScript)
}

func TestDeferStatement_RunAddsStatementsToDeferredScope(t *testing.T) {
	stmt := new(DeferStatement)
	_, _, err := stmt.Parse([]any{
		map[string]any{"explain": "first"},
		map[string]any{"explain": "second"},
	})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	assert.Len(t, scope.Deferred, 2)
}

func TestDeferStatement_RunWhenHasReturnedIsNoop(t *testing.T) {
	stmt := new(DeferStatement)
	_, _, err := stmt.Parse([]any{
		map[string]any{"explain": "first"},
	})
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)
	scope.HasReturned = true

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	assert.Nil(t, scope.Deferred)
}
