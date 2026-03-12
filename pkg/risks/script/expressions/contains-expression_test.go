package expressions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestContainsExpression_ParseBool_MapWithItemIn(t *testing.T) {
	script := map[string]any{
		"item": "git",
		"in":   "{tags}",
	}
	expr := new(ContainsExpression)
	result, errorScript, err := expr.ParseBool(script)
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	assert.NotNil(t, expr.item)
	assert.NotNil(t, expr.in)
}

func TestContainsExpression_EvalBool_ItemInArray_ReturnsTrue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("tags", common.SomeValue([]any{"git", "docker", "ci"}, nil))

	script := map[string]any{
		"item": "git",
		"in":   "{tags}",
	}
	expr := new(ContainsExpression)
	_, _, _ = expr.ParseBool(script)

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}

func TestContainsExpression_EvalBool_ItemNotInArray_ReturnsFalse(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("tags", common.SomeValue([]any{"docker", "ci"}, nil))

	script := map[string]any{
		"item": "git",
		"in":   "{tags}",
	}
	expr := new(ContainsExpression)
	_, _, _ = expr.ParseBool(script)

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.False(t, result.BoolValue())
}
