package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestScope_Init(t *testing.T) {
	scope := &Scope{}
	cat := &types.RiskCategory{
		ID:    "test-risk",
		Title: "Test Risk",
	}

	err := scope.Init(cat, nil)
	assert.NoError(t, err)
	assert.Same(t, cat, scope.Category)
	assert.NotNil(t, scope.Risk)
	assert.Equal(t, "test-risk", scope.Risk["id"])
}

func TestScope_SetModel(t *testing.T) {
	scope := &Scope{}
	model := &types.Model{
		ThreagileVersion: "1.0",
	}

	err := scope.SetModel(model)
	assert.NoError(t, err)
	assert.NotNil(t, scope.Model)
}

func TestScope_Set_Get_LocalVariable(t *testing.T) {
	scope := &Scope{}
	scope.Set("myvar", SomeStringValue("hello", nil))

	val, ok := scope.Get("myvar")
	assert.True(t, ok)
	assert.Equal(t, "hello", val.Value())
}

func TestScope_Get_ModelPrefix(t *testing.T) {
	scope := &Scope{}
	scope.Model = map[string]any{
		"title": "my model",
	}

	val, ok := scope.Get("$model.title")
	assert.True(t, ok)
	assert.Equal(t, "my model", val.Value())
}

func TestScope_Get_RiskPrefix(t *testing.T) {
	scope := &Scope{}
	cat := &types.RiskCategory{
		ID:    "test-risk",
		Title: "Test Risk",
	}
	err := scope.Init(cat, nil)
	assert.NoError(t, err)

	val, ok := scope.Get("$risk.id")
	assert.True(t, ok)
	assert.Equal(t, "test-risk", val.Value())
}

func TestScope_Get_DotPrefix_Item(t *testing.T) {
	scope := &Scope{}
	itemData := map[string]any{
		"name": "test-item",
	}
	scope.SetItem(SomeValue(itemData, NewEvent(NewBlankProperty(), NewPath("item"))))

	val, ok := scope.Get(".name")
	assert.True(t, ok)
	assert.Equal(t, "test-item", val.Value())
}

func TestScope_Get_Unknown(t *testing.T) {
	scope := &Scope{}
	_, ok := scope.Get("nonexistent")
	assert.False(t, ok)
}

func TestScope_Clone(t *testing.T) {
	scope := &Scope{}
	scope.Set("x", SomeStringValue("original", nil))

	child, err := scope.Clone()
	assert.NoError(t, err)
	assert.Same(t, scope, child.Parent)

	val, ok := child.Get("x")
	assert.True(t, ok)
	assert.Equal(t, "original", val.Value())
}

func TestScope_Clone_IsolatedVars(t *testing.T) {
	scope := &Scope{}
	scope.Set("x", SomeStringValue("original", nil))

	child, err := scope.Clone()
	assert.NoError(t, err)

	child.Set("x", SomeStringValue("changed", nil))

	parentVal, _ := scope.Get("x")
	assert.Equal(t, "original", parentVal.Value())

	childVal, _ := child.Get("x")
	assert.Equal(t, "changed", childVal.Value())
}

func TestScope_SetItem_GetItem_PopItem(t *testing.T) {
	scope := &Scope{}
	val := SomeStringValue("item-val", nil)

	scope.SetItem(val)
	assert.Same(t, val, scope.GetItem())

	popped := scope.PopItem()
	assert.Same(t, val, popped)
	assert.Nil(t, scope.GetItem())
}

func TestScope_SetReturnValue_GetReturnValue(t *testing.T) {
	scope := &Scope{}
	val := SomeStringValue("result", nil)

	scope.SetReturnValue(val)
	assert.Same(t, val, scope.GetReturnValue())
}

func TestScope_PushCall_PopCall(t *testing.T) {
	scope := &Scope{}
	event := NewEvent(NewTrueProperty(), NewPath("call1"))

	h := scope.PushCall(event)
	assert.Len(t, h, 1)
	assert.Len(t, scope.CallStack, 1)

	scope.PopCall()
	assert.Empty(t, scope.CallStack)
}

func TestScope_PushCall_Multiple(t *testing.T) {
	scope := &Scope{}
	e1 := NewEvent(NewTrueProperty(), NewPath("call1"))
	e2 := NewEvent(NewFalseProperty(), NewPath("call2"))

	scope.PushCall(e1)
	scope.PushCall(e2)
	assert.Len(t, scope.CallStack, 2)

	scope.PopCall()
	assert.Len(t, scope.CallStack, 1)
}

type dummyStatement struct{}

func (d *dummyStatement) Run(_ *Scope) (string, error) { return "", nil }
func (d *dummyStatement) Literal() string               { return "dummy" }

func TestScope_Defer(t *testing.T) {
	scope := &Scope{}
	stmt := &dummyStatement{}

	scope.Defer(stmt)
	assert.Len(t, scope.Deferred, 1)
	assert.Same(t, stmt, scope.Deferred[0])
}
