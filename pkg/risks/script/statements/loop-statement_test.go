package statements

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestLoopStatement_ParseWithInItemDoSucceeds(t *testing.T) {
	stmt := new(LoopStatement)
	result, errScript, err := stmt.Parse(map[string]any{
		"in":   "my_list",
		"item": "elem",
		"do": map[string]any{
			"assign": map[string]any{"last": "elem"},
		},
	})
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
}

func TestLoopStatement_ParseWithIndexSucceeds(t *testing.T) {
	stmt := new(LoopStatement)
	result, errScript, err := stmt.Parse(map[string]any{
		"in":    "my_list",
		"item":  "elem",
		"index": "idx",
		"do": map[string]any{
			"assign": map[string]any{"last": "elem"},
		},
	})
	assert.NoError(t, err)
	assert.Nil(t, errScript)
	assert.NotNil(t, result)
}

func TestLoopStatement_ParseWithUnknownKeyReturnsError(t *testing.T) {
	stmt := new(LoopStatement)
	_, _, err := stmt.Parse(map[string]any{
		"in":      "my_list",
		"item":    "elem",
		"unknown": "bad",
		"do": map[string]any{
			"assign": map[string]any{"last": "elem"},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected keyword")
}

func TestLoopStatement_RunIteratesOverArrayItems(t *testing.T) {
	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	scope.Set("my_list", common.SomeValue([]any{"a", "b", "c"}, nil))

	stmt := new(LoopStatement)
	_, _, err := stmt.Parse(map[string]any{
		"in":   "{my_list}",
		"item": "elem",
		"do": map[string]any{
			"assign": map[string]any{"last": "{elem}"},
		},
	})
	assert.NoError(t, err)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	val, ok := scope.Get("last")
	assert.True(t, ok)
	assert.Equal(t, "c", val.Value())
}

func TestLoopStatement_RunIteratesOverMapItems(t *testing.T) {
	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	scope.Set("my_map", common.SomeValue(map[string]any{"key1": "val1"}, nil))

	stmt := new(LoopStatement)
	_, _, err := stmt.Parse(map[string]any{
		"in":    "{my_map}",
		"item":  "elem",
		"index": "idx",
		"do": map[string]any{
			"assign": map[string]any{"last_key": "{idx}"},
		},
	})
	assert.NoError(t, err)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	val, ok := scope.Get("last_key")
	assert.True(t, ok)
	assert.Equal(t, "key1", val.Value())
}

func TestLoopStatement_RunStopsWhenBodySetsHasReturned(t *testing.T) {
	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)

	scope.Set("my_list", common.SomeValue([]any{"a", "b", "c"}, nil))

	stmt := new(LoopStatement)
	_, _, err := stmt.Parse(map[string]any{
		"in":   "{my_list}",
		"item": "elem",
		"do": map[string]any{
			"return": "{elem}",
		},
	})
	assert.NoError(t, err)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)
	assert.True(t, scope.HasReturned)

	retVal := scope.GetReturnValue()
	assert.NotNil(t, retVal)
	assert.Equal(t, "a", retVal.PlainValue())
}

func TestLoopStatement_RunWhenHasReturnedIsNoop(t *testing.T) {
	scope := new(common.Scope)
	initErr := scope.Init(nil, nil)
	assert.NoError(t, initErr)
	scope.HasReturned = true

	scope.Set("my_list", common.SomeValue([]any{"a", "b"}, nil))

	stmt := new(LoopStatement)
	_, _, err := stmt.Parse(map[string]any{
		"in":   "{my_list}",
		"item": "elem",
		"do": map[string]any{
			"assign": map[string]any{"last": "{elem}"},
		},
	})
	assert.NoError(t, err)

	errLiteral, runErr := stmt.Run(scope)
	assert.NoError(t, runErr)
	assert.Empty(t, errLiteral)

	_, ok := scope.Get("last")
	assert.False(t, ok)
}
