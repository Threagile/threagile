package statements

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestReturnStatement_ParseStringSucceeds(t *testing.T) {
	stmt := new(ReturnStatement)
	result, errScript, err := stmt.Parse("hello")
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
}

func TestReturnStatement_ParseBoolSucceeds(t *testing.T) {
	stmt := new(ReturnStatement)
	result, errScript, err := stmt.Parse(true)
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
}

func TestReturnStatement_RunSetsReturnValueAndHasReturned(t *testing.T) {
	stmt := new(ReturnStatement)
	_, _, err := stmt.Parse("hello")
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)
	assert.True(t, scope.HasReturned)

	retVal := scope.GetReturnValue()
	assert.NotNil(t, retVal)
	assert.Equal(t, "hello", retVal.PlainValue())
}

func TestReturnStatement_RunWhenAlreadyReturnedIsNoop(t *testing.T) {
	stmt := new(ReturnStatement)
	_, _, err := stmt.Parse("hello")
	assert.NoError(t, err)

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)
	scope.HasReturned = true

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)
	assert.Nil(t, scope.GetReturnValue())
}

func TestReturnStatement_RunWithNilExpressionIsNoop(t *testing.T) {
	stmt := &ReturnStatement{}

	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)
	assert.False(t, scope.HasReturned)
}
