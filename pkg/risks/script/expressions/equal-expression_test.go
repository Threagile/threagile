package expressions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestParseEqualExpression(t *testing.T) {
	expression, errorScript, parseError := new(EqualExpression).ParseBool(map[string]interface{}{
		"first":  "value1",
		"second": "value2",
		"as":     "",
	})

	assert.Equal(t, nil, parseError)
	assert.Equal(t, nil, errorScript)
	assert.IsType(t, &EqualExpression{}, expression)
}

func TestParseErrorEqualExpression(t *testing.T) {
	expression, errorScript, parseError := new(EqualExpression).ParseBool(map[string]interface{}{
		"first0": "value1",
		"second": "value2",
	})

	assert.NotEqual(t, nil, parseError)
	assert.Equal(t, "failed to parse equal-expression: unexpected keyword \"first0\"", parseError.Error())
	assert.Equal(t, map[string]interface{}{"first0": "value1", "second": "value2"}, errorScript)
	assert.IsType(t, nil, expression)
}

func TestEvalTrueEqualExpression(t *testing.T) {
	expression, errorScript, parseError := new(EqualExpression).ParseBool(map[string]interface{}{
		"first":  "value1",
		"second": "value1",
	})

	assert.Equal(t, nil, parseError)
	assert.Equal(t, nil, errorScript)
	assert.IsType(t, &EqualExpression{}, expression)

	result, errorLiteral, evalError := expression.EvalBool(new(common.Scope))

	assert.Equal(t, nil, evalError)
	assert.Equal(t, "", errorLiteral)
	assert.IsType(t, &common.BoolValue{}, result)

	assert.Equal(t, true, result.BoolValue())
}

func TestEvalFalseEqualExpression(t *testing.T) {
	expression, errorScript, parseError := new(EqualExpression).ParseBool(map[string]interface{}{
		"first":  "value1",
		"second": "value2",
	})

	assert.Equal(t, nil, parseError)
	assert.Equal(t, nil, errorScript)
	assert.IsType(t, &EqualExpression{}, expression)

	result, errorLiteral, evalError := expression.EvalBool(new(common.Scope))

	assert.Equal(t, nil, evalError)
	assert.Equal(t, "", errorLiteral)
	assert.IsType(t, &common.BoolValue{}, result)

	assert.Equal(t, false, result.BoolValue())
}
