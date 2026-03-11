package expressions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestAndExpression_ParseBool_ArrayOfBoolExpressions(t *testing.T) {
	// Parse with an array of bool-valued expressions (strings that will become ValueExpressions)
	script := []any{"true", "true"}
	expr := new(AndExpression)
	result, errorScript, err := expr.ParseBool(script)
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	assert.Len(t, expr.expressions, 2)
}

func TestAndExpression_EvalBool_AllTrue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	// Build an AndExpression with two true ValueExpressions
	trueExpr1 := new(ValueExpression)
	_, _, _ = trueExpr1.ParseBool(true)
	trueExpr2 := new(ValueExpression)
	_, _, _ = trueExpr2.ParseBool(true)

	expr := &AndExpression{
		expressions: []common.BoolExpression{trueExpr1, trueExpr2},
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}

func TestAndExpression_EvalBool_OneFalse_ShortCircuits(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	trueExpr := new(ValueExpression)
	_, _, _ = trueExpr.ParseBool(true)
	falseExpr := new(ValueExpression)
	_, _, _ = falseExpr.ParseBool(false)

	expr := &AndExpression{
		expressions: []common.BoolExpression{falseExpr, trueExpr},
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.False(t, result.BoolValue())
}

func TestAndExpression_EvalBool_Empty_ReturnsTrue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := &AndExpression{
		expressions: []common.BoolExpression{},
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}
