package expressions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestEqualExpression_ParseBool_MapWithFirstSecond(t *testing.T) {
	script := map[string]any{
		"first":  "a",
		"second": "b",
	}
	expr := new(EqualExpression)
	result, errorScript, err := expr.ParseBool(script)
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	assert.NotNil(t, expr.first)
	assert.NotNil(t, expr.second)
}

func TestEqualExpression_EvalBool_EqualStrings_ReturnsTrue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	script := map[string]any{
		"first":  "hello",
		"second": "hello",
	}
	expr := new(EqualExpression)
	_, _, _ = expr.ParseBool(script)

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}

func TestEqualExpression_EvalBool_DifferentStrings_ReturnsFalse(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	script := map[string]any{
		"first":  "hello",
		"second": "world",
	}
	expr := new(EqualExpression)
	_, _, _ = expr.ParseBool(script)

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.False(t, result.BoolValue())
}
