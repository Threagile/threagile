package expressions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestFalseExpression_ParseBool_FalseString(t *testing.T) {
	expr := new(FalseExpression)
	result, errorScript, err := expr.ParseBool("false")
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
}

func TestFalseExpression_EvalBool_VariableIsTrue_ReturnsFalse(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("flag", common.SomeBoolValue(true, nil))

	innerExpr := new(ValueExpression)
	_, _, _ = innerExpr.ParseBool("{flag}")

	expr := &FalseExpression{
		expression: innerExpr,
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.False(t, result.BoolValue())
}

func TestFalseExpression_EvalBool_VariableIsFalse_ReturnsTrue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("flag", common.SomeBoolValue(false, nil))

	innerExpr := new(ValueExpression)
	_, _, _ = innerExpr.ParseBool("{flag}")

	expr := &FalseExpression{
		expression: innerExpr,
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}
