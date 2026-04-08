package expressions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestExpressionList_ParseExpression_DispatchesTrue(t *testing.T) {
	script := map[string]any{
		"true": "true",
	}
	el := new(ExpressionList)
	result, errorScript, err := el.ParseExpression(script)
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	_, ok := result.(*TrueExpression)
	assert.True(t, ok, "expected TrueExpression, got %T", result)
}

func TestExpressionList_ParseExpression_DispatchesAnd(t *testing.T) {
	script := map[string]any{
		"and": []any{"true", "true"},
	}
	el := new(ExpressionList)
	result, errorScript, err := el.ParseExpression(script)
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	_, ok := result.(*AndExpression)
	assert.True(t, ok, "expected AndExpression, got %T", result)
}

func TestExpressionList_ParseExpression_UnknownKey_ReturnsError(t *testing.T) {
	script := map[string]any{
		"unknown-keyword": "value",
	}
	el := new(ExpressionList)
	_, _, err := el.ParseExpression(script)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected keyword")
}

func TestExpressionList_ParseAny_MapDelegatesToParseExpression(t *testing.T) {
	script := map[string]any{
		"true": "true",
	}
	el := new(ExpressionList)
	result, errorScript, err := el.ParseAny(script)
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	_, ok := result.(*TrueExpression)
	assert.True(t, ok, "expected TrueExpression, got %T", result)
}

func TestExpressionList_ParseAny_StringDelegatesToValueExpression(t *testing.T) {
	el := new(ExpressionList)
	result, errorScript, err := el.ParseAny("hello")
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	_, ok := result.(*ValueExpression)
	assert.True(t, ok, "expected ValueExpression, got %T", result)
}

func TestExpressionList_ParseAny_SingleElementArray_Unwraps(t *testing.T) {
	script := []any{"hello"}
	el := new(ExpressionList)
	result, errorScript, err := el.ParseAny(script)
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	// Single-element array should unwrap to the inner expression
	_, ok := result.(*ValueExpression)
	assert.True(t, ok, "expected ValueExpression from single-element array unwrap, got %T", result)
}

func TestExpressionList_EvalAny_NilExpressions_ReturnsNil(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	el := &ExpressionList{
		expressions: nil,
	}

	result, errorLiteral, err := el.EvalAny(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.Nil(t, result)
}

func TestExpressionList_EvalAny_SingleExpression_EvaluatesIt(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	valueExpr := new(ValueExpression)
	_, _, _ = valueExpr.ParseAny("hello")

	el := &ExpressionList{
		expressions: []common.Expression{valueExpr},
	}

	result, errorLiteral, err := el.EvalAny(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.Equal(t, "hello", result.Value())
}

func TestExpressionList_EvalAny_MultipleExpressions_ReturnsArray(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr1 := new(ValueExpression)
	_, _, _ = expr1.ParseAny("first")
	expr2 := new(ValueExpression)
	_, _, _ = expr2.ParseAny("second")

	el := &ExpressionList{
		expressions: []common.Expression{expr1, expr2},
	}

	result, errorLiteral, err := el.EvalAny(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.NotNil(t, result)
	// Multiple expressions should produce an ArrayValue
	arrayValue, ok := result.(*common.ArrayValue)
	assert.True(t, ok, "expected ArrayValue, got %T", result)
	assert.Len(t, arrayValue.ArrayValue(), 2)
}
