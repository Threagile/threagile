package expressions

import (
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestValueExpression_ParseValue_StoresScriptValue(t *testing.T) {
	expr := new(ValueExpression)
	result, errorScript, err := expr.ParseValue("hello")
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	assert.Equal(t, "hello", expr.value)
}

func TestValueExpression_ParseString_StoresScriptValue(t *testing.T) {
	expr := new(ValueExpression)
	result, errorScript, err := expr.ParseString("world")
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	assert.Equal(t, "world", expr.value)
}

func TestValueExpression_ParseBool_StoresScriptValue(t *testing.T) {
	expr := new(ValueExpression)
	result, errorScript, err := expr.ParseBool("true")
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	assert.Equal(t, "true", expr.value)
}

func TestValueExpression_ParseDecimal_StoresScriptValue(t *testing.T) {
	expr := new(ValueExpression)
	result, errorScript, err := expr.ParseDecimal("42")
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	assert.Equal(t, "42", expr.value)
}

func TestValueExpression_ParseArray_StoresScriptValue(t *testing.T) {
	expr := new(ValueExpression)
	input := []any{"a", "b"}
	result, errorScript, err := expr.ParseArray(input)
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
}

func TestValueExpression_ParseAny_StoresScriptValue(t *testing.T) {
	expr := new(ValueExpression)
	result, errorScript, err := expr.ParseAny("anything")
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	assert.Equal(t, "anything", expr.value)
}

func TestValueExpression_EvalString_PlainString(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := new(ValueExpression)
	_, _, _ = expr.ParseString("hello")

	result, errorLiteral, err := expr.EvalString(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.Equal(t, "hello", result.StringValue())
}

func TestValueExpression_EvalBool_TrueString(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := new(ValueExpression)
	_, _, _ = expr.ParseBool("true")

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}

func TestValueExpression_EvalBool_FalseString(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := new(ValueExpression)
	_, _, _ = expr.ParseBool("false")

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.False(t, result.BoolValue())
}

func TestValueExpression_EvalBool_BoolValue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := new(ValueExpression)
	_, _, _ = expr.ParseBool(true)

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}

func TestValueExpression_EvalDecimal_DecimalValue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := new(ValueExpression)
	dec := decimal.NewFromInt(42)
	_, _, _ = expr.ParseDecimal(dec)

	result, errorLiteral, err := expr.EvalDecimal(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, dec.Equal(result.DecimalValue()))
}

func TestValueExpression_EvalAny_StringReturnsString(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := new(ValueExpression)
	_, _, _ = expr.ParseAny("hello")

	result, errorLiteral, err := expr.EvalAny(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.Equal(t, "hello", result.Value())
}

func TestValueExpression_EvalAny_BoolReturnsBool(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := new(ValueExpression)
	_, _, _ = expr.ParseAny(true)

	result, errorLiteral, err := expr.EvalAny(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.Equal(t, true, result.Value())
}

func TestValueExpression_EvalDecimal_StringNumber(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := new(ValueExpression)
	_, _, _ = expr.ParseDecimal("3.14")

	result, _, err := expr.EvalDecimal(scope)
	assert.NoError(t, err)
	expected, _ := decimal.NewFromString("3.14")
	assert.True(t, expected.Equal(result.DecimalValue()))
}

func TestValueExpression_EvalArray_ArrayInput(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	input := []any{"a", "b", "c"}
	expr := new(ValueExpression)
	_, _, _ = expr.ParseArray(input)

	result, _, err := expr.EvalArray(scope)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.ArrayValue(), 3)
}

func TestValueExpression_EvalString_VariableReference(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("varname", common.SomeStringValue("resolved", nil))

	expr := new(ValueExpression)
	_, _, _ = expr.ParseString("{varname}")

	result, errorLiteral, err := expr.EvalString(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.Equal(t, "resolved", result.StringValue())
}

func TestValueExpression_EvalAny_VariableReference(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("myvar", common.SomeStringValue("myvalue", nil))

	expr := new(ValueExpression)
	_, _, _ = expr.ParseAny("{myvar}")

	result, errorLiteral, err := expr.EvalAny(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.Equal(t, "myvalue", result.PlainValue())
}

func TestValueExpression_EvalAny_VariableNotFound_ReturnsNil(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := new(ValueExpression)
	_, _, _ = expr.ParseAny("{nonexistent}")

	result, _, err := expr.EvalAny(scope)
	assert.NoError(t, err)
	// When the variable is not found, scope.Get returns (nil, false),
	// so evalStringReference returns a nil Value interface.
	assert.Nil(t, result)
}

func TestValueExpression_EvalAny_MethodCall(t *testing.T) {
	scope := new(common.Scope)
	methods := map[string]common.Statement{
		"methodname": &mockStatement{returnValue: common.SomeStringValue("method-result", nil)},
	}
	_ = scope.Init(nil, methods)

	expr := new(ValueExpression)
	_, _, _ = expr.ParseAny("methodname(arg)")

	result, errorLiteral, err := expr.EvalAny(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.Equal(t, "method-result", result.PlainValue())
}

func TestValueExpression_EvalAny_BuiltInCalculateSeverity(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := new(ValueExpression)
	_, _, _ = expr.ParseAny("calculate_severity(unlikely, low)")

	result, errorLiteral, err := expr.EvalAny(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.NotNil(t, result)
	// calculate_severity returns a severity string
	assert.IsType(t, "", result.PlainValue())
}

// mockStatement implements common.Statement for testing method calls.
type mockStatement struct {
	returnValue common.Value
}

func (m *mockStatement) Run(scope *common.Scope) (string, error) {
	scope.SetReturnValue(m.returnValue)
	return "", nil
}

func (m *mockStatement) Literal() string {
	return "mock"
}
