package expressions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestGreaterExpression_ParseBool_WithAs(t *testing.T) {
	script := map[string]any{
		"first":  "critical",
		"second": "important",
		"as":     "criticality",
	}
	expr := new(GreaterExpression)
	result, errorScript, err := expr.ParseBool(script)
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	assert.NotNil(t, expr.first)
	assert.NotNil(t, expr.second)
	assert.NotNil(t, expr.as)
}

func TestGreaterExpression_EvalBool_FirstGreater_ReturnsTrue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	script := map[string]any{
		"first":  "critical",
		"second": "important",
		"as":     "criticality",
	}
	expr := new(GreaterExpression)
	_, _, _ = expr.ParseBool(script)

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}

func TestGreaterExpression_EvalBool_FirstLessOrEqual_ReturnsFalse(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	script := map[string]any{
		"first":  "important",
		"second": "critical",
		"as":     "criticality",
	}
	expr := new(GreaterExpression)
	_, _, _ = expr.ParseBool(script)

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.False(t, result.BoolValue())
}
