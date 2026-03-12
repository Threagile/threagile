package expressions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestTrueExpression_ParseBool_TrueString(t *testing.T) {
	expr := new(TrueExpression)
	result, errorScript, err := expr.ParseBool("true")
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
}

func TestTrueExpression_EvalBool_VariableIsTrue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("flag", common.SomeBoolValue(true, nil))

	innerExpr := new(ValueExpression)
	_, _, _ = innerExpr.ParseBool("{flag}")

	expr := &TrueExpression{
		expression: innerExpr,
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}

func TestTrueExpression_EvalBool_VariableIsFalse(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("flag", common.SomeBoolValue(false, nil))

	innerExpr := new(ValueExpression)
	_, _, _ = innerExpr.ParseBool("{flag}")

	expr := &TrueExpression{
		expression: innerExpr,
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.False(t, result.BoolValue())
}
