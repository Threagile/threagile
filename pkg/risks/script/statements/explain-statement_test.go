package statements

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestExplainStatement_ParseStringSucceeds(t *testing.T) {
	stmt := new(ExplainStatement)
	result, errScript, err := stmt.Parse("some explanation")
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
}

func TestExplainStatement_ParseNonStringExpressionReturnsError(t *testing.T) {
	stmt := new(ExplainStatement)
	_, _, err := stmt.Parse(map[string]any{
		"count": "some_list",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestExplainStatement_RunSetsExplainOnScope(t *testing.T) {
	stmt := new(ExplainStatement)
	_, _, err := stmt.Parse("some explanation")
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	assert.NotNil(t, scope.Explain)
	assert.Equal(t, stmt, scope.Explain)
}

func TestExplainStatement_RunWhenHasReturnedIsNoop(t *testing.T) {
	stmt := new(ExplainStatement)
	_, _, err := stmt.Parse("some explanation")
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)
	scope.HasReturned = true

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	assert.Nil(t, scope.Explain)
}

func TestExplainStatement_EvalReturnsString(t *testing.T) {
	stmt := new(ExplainStatement)
	_, _, err := stmt.Parse("some explanation")
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	result := stmt.Eval(scope)
	assert.Equal(t, "some explanation", result)
}
