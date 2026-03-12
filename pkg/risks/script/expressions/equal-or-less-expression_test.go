package expressions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestEqualOrLessExpression_EvalBool_Equal_ReturnsTrue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	script := map[string]any{
		"first":  "critical",
		"second": "critical",
		"as":     "criticality",
	}
	expr := new(EqualOrLessExpression)
	_, _, _ = expr.ParseBool(script)

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}

func TestEqualOrLessExpression_EvalBool_Less_ReturnsTrue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	script := map[string]any{
		"first":  "important",
		"second": "critical",
		"as":     "criticality",
	}
	expr := new(EqualOrLessExpression)
	_, _, _ = expr.ParseBool(script)

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}

func TestEqualOrLessExpression_EvalBool_Greater_ReturnsFalse(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	script := map[string]any{
		"first":  "critical",
		"second": "important",
		"as":     "criticality",
	}
	expr := new(EqualOrLessExpression)
	_, _, _ = expr.ParseBool(script)

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.False(t, result.BoolValue())
}
