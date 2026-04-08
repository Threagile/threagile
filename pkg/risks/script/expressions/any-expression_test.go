package expressions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestAnyExpression_ParseBool(t *testing.T) {
	expr := new(AnyExpression)
	script := map[string]any{
		"in": "{items}",
		"true": "{.active}",
	}

	result, _, err := expr.ParseBool(script)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestAnyExpression_ParseBool_WithItemAndIndex(t *testing.T) {
	expr := new(AnyExpression)
	script := map[string]any{
		"in":    "{items}",
		"item":  "it",
		"index": "idx",
		"true":  "{it.active}",
	}

	result, _, err := expr.ParseBool(script)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestAnyExpression_ParseBool_InvalidFormat(t *testing.T) {
	expr := new(AnyExpression)
	_, _, err := expr.ParseBool("not-a-map")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected map[string]any")
}

func TestAnyExpression_EvalBool_ArrayWithMatch(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	items := common.SomeValue([]any{
		map[string]any{"active": true},
		map[string]any{"active": false},
	}, common.EmptyEvent())
	scope.Set("items", items)

	expr := new(AnyExpression)
	script := map[string]any{
		"in":   "{items}",
		"true": "{.active}",
	}
	_, _, parseErr := expr.ParseBool(script)
	assert.NoError(t, parseErr)

	result, _, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.True(t, result.BoolValue(), "any should return true when at least one item matches")
}

func TestAnyExpression_EvalBool_ArrayNoMatch(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	items := common.SomeValue([]any{
		map[string]any{"active": false},
		map[string]any{"active": false},
	}, common.EmptyEvent())
	scope.Set("items", items)

	expr := new(AnyExpression)
	script := map[string]any{
		"in":   "{items}",
		"true": "{.active}",
	}
	_, _, parseErr := expr.ParseBool(script)
	assert.NoError(t, parseErr)

	result, _, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.False(t, result.BoolValue(), "any should return false when no items match")
}

func TestAnyExpression_EvalBool_MapWithMatch(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	items := common.SomeValue(map[string]any{
		"a": map[string]any{"active": true},
		"b": map[string]any{"active": false},
	}, common.EmptyEvent())
	scope.Set("items", items)

	expr := new(AnyExpression)
	script := map[string]any{
		"in":   "{items}",
		"true": "{.active}",
	}
	_, _, parseErr := expr.ParseBool(script)
	assert.NoError(t, parseErr)

	result, _, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.True(t, result.BoolValue(), "any over map should return true when at least one value matches")
}

func TestAnyExpression_EvalBool_MapNoMatch(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	items := common.SomeValue(map[string]any{
		"a": map[string]any{"active": false},
		"b": map[string]any{"active": false},
	}, common.EmptyEvent())
	scope.Set("items", items)

	expr := new(AnyExpression)
	script := map[string]any{
		"in":   "{items}",
		"true": "{.active}",
	}
	_, _, parseErr := expr.ParseBool(script)
	assert.NoError(t, parseErr)

	result, _, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.False(t, result.BoolValue(), "any over map should return false when no values match")
}

func TestAnyExpression_EvalBool_EmptyArrayNoExpression(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	items := common.SomeValue([]any{}, common.EmptyEvent())
	scope.Set("items", items)

	expr := new(AnyExpression)
	script := map[string]any{
		"in": "{items}",
	}
	_, _, parseErr := expr.ParseBool(script)
	assert.NoError(t, parseErr)

	result, _, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.True(t, result.BoolValue(), "any with no expression returns true (vacuous)")
}

func TestAnyExpression_EvalBool_NilValue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	scope.Set("items", common.NilValue())

	expr := new(AnyExpression)
	script := map[string]any{
		"in":   "{items}",
		"true": "{.}",
	}
	_, _, parseErr := expr.ParseBool(script)
	assert.NoError(t, parseErr)

	result, _, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.False(t, result.BoolValue(), "any over nil returns false")
}

func TestAnyExpression_EvalBool_MapWithIndex(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	items := common.SomeValue(map[string]any{
		"first":  map[string]any{"val": true},
		"second": map[string]any{"val": false},
	}, common.EmptyEvent())
	scope.Set("items", items)

	expr := new(AnyExpression)
	script := map[string]any{
		"in":    "{items}",
		"index": "key",
		"true":  "{.val}",
	}
	_, _, parseErr := expr.ParseBool(script)
	assert.NoError(t, parseErr)

	result, _, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.True(t, result.BoolValue(), "any over map with match should return true")
}
