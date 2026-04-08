package expressions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestOrExpression_ParseBool_ArrayOfBoolExpressions(t *testing.T) {
	script := []any{"true", "false"}
	expr := new(OrExpression)
	result, errorScript, err := expr.ParseBool(script)
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	assert.Len(t, expr.expressions, 2)
}

func TestOrExpression_EvalBool_OneTrue_ShortCircuits(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	trueExpr := new(ValueExpression)
	_, _, _ = trueExpr.ParseBool(true)
	falseExpr := new(ValueExpression)
	_, _, _ = falseExpr.ParseBool(false)

	expr := &OrExpression{
		expressions: []common.BoolExpression{trueExpr, falseExpr},
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}

func TestOrExpression_EvalBool_AllFalse(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	falseExpr1 := new(ValueExpression)
	_, _, _ = falseExpr1.ParseBool(false)
	falseExpr2 := new(ValueExpression)
	_, _, _ = falseExpr2.ParseBool(false)

	expr := &OrExpression{
		expressions: []common.BoolExpression{falseExpr1, falseExpr2},
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.False(t, result.BoolValue())
}

func TestOrExpression_EvalBool_Empty_ReturnsFalse(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := &OrExpression{
		expressions: []common.BoolExpression{},
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.False(t, result.BoolValue())
}
