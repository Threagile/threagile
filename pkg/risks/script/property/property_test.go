package property

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- Blank ---

func TestNewBlank_ReturnsNonNil(t *testing.T) {
	b := NewBlank()
	assert.NotNil(t, b)
}

func TestBlank_Negated_ReturnsFalse(t *testing.T) {
	b := NewBlank()
	assert.False(t, b.Negated())
}

func TestBlank_Text_ReturnsEmptySlice(t *testing.T) {
	b := NewBlank()
	assert.Equal(t, []string{}, b.Text())
}

func TestBlank_Negate_IsNoOp(t *testing.T) {
	b := NewBlank()
	b.Negate()
	assert.False(t, b.Negated())
	assert.Equal(t, []string{}, b.Text())
}

func TestBlank_DoubleNegate_IsNoOp(t *testing.T) {
	b := NewBlank()
	b.Negate()
	b.Negate()
	assert.False(t, b.Negated())
	assert.Equal(t, []string{}, b.Text())
}

// --- Equal ---

func TestNewEqual_ReturnsNonNil(t *testing.T) {
	e := NewEqual()
	assert.NotNil(t, e)
}

func TestEqual_Negated_DefaultFalse(t *testing.T) {
	e := NewEqual()
	assert.False(t, e.Negated())
}

func TestEqual_Text_Default(t *testing.T) {
	e := NewEqual()
	assert.Equal(t, []string{"equal to"}, e.Text())
}

func TestEqual_Negate_SetsNegated(t *testing.T) {
	e := NewEqual()
	e.Negate()
	assert.True(t, e.Negated())
	assert.Equal(t, []string{"not equal to"}, e.Text())
}

func TestEqual_DoubleNegate_RestoresOriginal(t *testing.T) {
	e := NewEqual()
	e.Negate()
	e.Negate()
	assert.False(t, e.Negated())
	assert.Equal(t, []string{"equal to"}, e.Text())
}

func TestEqual_Path_DoesNotPanic(t *testing.T) {
	e := NewEqual()
	assert.NotPanics(t, func() { e.Path() })
}

// --- NotEqual ---

func TestNewNotEqual_ReturnsNonNil(t *testing.T) {
	ne := NewNotEqual()
	assert.NotNil(t, ne)
}

func TestNotEqual_Negated_DefaultFalse(t *testing.T) {
	ne := NewNotEqual()
	assert.False(t, ne.Negated())
}

func TestNotEqual_Text_Default(t *testing.T) {
	ne := NewNotEqual()
	assert.Equal(t, []string{"not equal to"}, ne.Text())
}

func TestNotEqual_Negate_SetsNegated(t *testing.T) {
	ne := NewNotEqual()
	ne.Negate()
	assert.True(t, ne.Negated())
	assert.Equal(t, []string{"equal to"}, ne.Text())
}

func TestNotEqual_DoubleNegate_RestoresOriginal(t *testing.T) {
	ne := NewNotEqual()
	ne.Negate()
	ne.Negate()
	assert.False(t, ne.Negated())
	assert.Equal(t, []string{"not equal to"}, ne.Text())
}

func TestNotEqual_Path_DoesNotPanic(t *testing.T) {
	ne := NewNotEqual()
	assert.NotPanics(t, func() { ne.Path() })
}

// --- Greater ---

func TestNewGreater_ReturnsNonNil(t *testing.T) {
	g := NewGreater()
	assert.NotNil(t, g)
}

func TestGreater_Negated_DefaultFalse(t *testing.T) {
	g := NewGreater()
	assert.False(t, g.Negated())
}

func TestGreater_Text_Default(t *testing.T) {
	g := NewGreater()
	assert.Equal(t, []string{"greater than"}, g.Text())
}

func TestGreater_Negate_SetsNegated(t *testing.T) {
	g := NewGreater()
	g.Negate()
	assert.True(t, g.Negated())
	assert.Equal(t, []string{"less than or equal to"}, g.Text())
}

func TestGreater_DoubleNegate_RestoresOriginal(t *testing.T) {
	g := NewGreater()
	g.Negate()
	g.Negate()
	assert.False(t, g.Negated())
	assert.Equal(t, []string{"greater than"}, g.Text())
}

func TestGreater_Path_DoesNotPanic(t *testing.T) {
	g := NewGreater()
	assert.NotPanics(t, func() { g.Path() })
}

// --- Less ---

func TestNewLess_ReturnsNonNil(t *testing.T) {
	l := NewLess()
	assert.NotNil(t, l)
}

func TestLess_Negated_DefaultFalse(t *testing.T) {
	l := NewLess()
	assert.False(t, l.Negated())
}

func TestLess_Text_Default(t *testing.T) {
	l := NewLess()
	assert.Equal(t, []string{"less than"}, l.Text())
}

func TestLess_Negate_SetsNegated(t *testing.T) {
	l := NewLess()
	l.Negate()
	assert.True(t, l.Negated())
	assert.Equal(t, []string{"greater than or equal to"}, l.Text())
}

func TestLess_DoubleNegate_RestoresOriginal(t *testing.T) {
	l := NewLess()
	l.Negate()
	l.Negate()
	assert.False(t, l.Negated())
	assert.Equal(t, []string{"less than"}, l.Text())
}

func TestLess_Path_DoesNotPanic(t *testing.T) {
	l := NewLess()
	assert.NotPanics(t, func() { l.Path() })
}

// --- GreaterOrEqual ---

func TestNewGreaterOrEqual_ReturnsNonNil(t *testing.T) {
	ge := NewGreaterOrEqual()
	assert.NotNil(t, ge)
}

func TestGreaterOrEqual_Negated_DefaultFalse(t *testing.T) {
	ge := NewGreaterOrEqual()
	assert.False(t, ge.Negated())
}

func TestGreaterOrEqual_Text_Default(t *testing.T) {
	ge := NewGreaterOrEqual()
	assert.Equal(t, []string{"greater than or equal to"}, ge.Text())
}

func TestGreaterOrEqual_Negate_SetsNegated(t *testing.T) {
	ge := NewGreaterOrEqual()
	ge.Negate()
	assert.True(t, ge.Negated())
	assert.Equal(t, []string{"less than"}, ge.Text())
}

func TestGreaterOrEqual_DoubleNegate_RestoresOriginal(t *testing.T) {
	ge := NewGreaterOrEqual()
	ge.Negate()
	ge.Negate()
	assert.False(t, ge.Negated())
	assert.Equal(t, []string{"greater than or equal to"}, ge.Text())
}

func TestGreaterOrEqual_Path_DoesNotPanic(t *testing.T) {
	ge := NewGreaterOrEqual()
	assert.NotPanics(t, func() { ge.Path() })
}

// --- LessOrEqual ---

func TestNewLessOrEqual_ReturnsNonNil(t *testing.T) {
	le := NewLessOrEqual()
	assert.NotNil(t, le)
}

func TestLessOrEqual_Negated_DefaultFalse(t *testing.T) {
	le := NewLessOrEqual()
	assert.False(t, le.Negated())
}

func TestLessOrEqual_Text_Default(t *testing.T) {
	le := NewLessOrEqual()
	assert.Equal(t, []string{"less than or equal to"}, le.Text())
}

func TestLessOrEqual_Negate_SetsNegated(t *testing.T) {
	le := NewLessOrEqual()
	le.Negate()
	assert.True(t, le.Negated())
	assert.Equal(t, []string{"greater than"}, le.Text())
}

func TestLessOrEqual_DoubleNegate_RestoresOriginal(t *testing.T) {
	le := NewLessOrEqual()
	le.Negate()
	le.Negate()
	assert.False(t, le.Negated())
	assert.Equal(t, []string{"less than or equal to"}, le.Text())
}

func TestLessOrEqual_Path_DoesNotPanic(t *testing.T) {
	le := NewLessOrEqual()
	assert.NotPanics(t, func() { le.Path() })
}

// --- True ---

func TestNewTrue_ReturnsNonNil(t *testing.T) {
	tr := NewTrue()
	assert.NotNil(t, tr)
}

func TestTrue_Negated_DefaultFalse(t *testing.T) {
	tr := NewTrue()
	assert.False(t, tr.Negated())
}

func TestTrue_Text_Default(t *testing.T) {
	tr := NewTrue()
	assert.Equal(t, []string{"true"}, tr.Text())
}

func TestTrue_Negate_SetsNegated(t *testing.T) {
	tr := NewTrue()
	tr.Negate()
	assert.True(t, tr.Negated())
	assert.Equal(t, []string{"false"}, tr.Text())
}

func TestTrue_DoubleNegate_RestoresOriginal(t *testing.T) {
	tr := NewTrue()
	tr.Negate()
	tr.Negate()
	assert.False(t, tr.Negated())
	assert.Equal(t, []string{"true"}, tr.Text())
}

// --- False ---

func TestNewFalse_ReturnsNonNil(t *testing.T) {
	f := NewFalse()
	assert.NotNil(t, f)
}

func TestFalse_Negated_DefaultFalse(t *testing.T) {
	f := NewFalse()
	assert.False(t, f.Negated())
}

func TestFalse_Text_Default(t *testing.T) {
	f := NewFalse()
	assert.Equal(t, []string{"false"}, f.Text())
}

func TestFalse_Negate_SetsNegated(t *testing.T) {
	f := NewFalse()
	f.Negate()
	assert.True(t, f.Negated())
	assert.Equal(t, []string{"true"}, f.Text())
}

func TestFalse_DoubleNegate_RestoresOriginal(t *testing.T) {
	f := NewFalse()
	f.Negate()
	f.Negate()
	assert.False(t, f.Negated())
	assert.Equal(t, []string{"false"}, f.Text())
}

func TestFalse_Value_DefaultReturnsFalse(t *testing.T) {
	f := NewFalse()
	assert.Equal(t, false, f.Value())
}

func TestFalse_Value_AfterNegateReturnsTrue(t *testing.T) {
	f := NewFalse()
	f.Negate()
	assert.Equal(t, true, f.Value())
}

// --- Value ---

func TestNewValue_ReturnsNonNil(t *testing.T) {
	v := NewValue("hello")
	assert.NotNil(t, v)
}

func TestValue_Negated_DefaultFalse(t *testing.T) {
	v := NewValue("hello")
	assert.False(t, v.Negated())
}

func TestValue_Text_StringDefault(t *testing.T) {
	v := NewValue("hello")
	assert.Equal(t, []string{"hello"}, v.Text())
}

func TestValue_Text_StringNegated(t *testing.T) {
	v := NewValue("hello")
	v.Negate()
	assert.True(t, v.Negated())
	assert.Equal(t, []string{"not hello"}, v.Text())
}

func TestValue_Text_IntDefault(t *testing.T) {
	v := NewValue(42)
	assert.Equal(t, []string{"42"}, v.Text())
}

func TestValue_Text_IntNegated(t *testing.T) {
	v := NewValue(42)
	v.Negate()
	assert.Equal(t, []string{"not 42"}, v.Text())
}

func TestValue_Text_SliceDefault(t *testing.T) {
	v := NewValue([]any{"a", "b", "c"})
	assert.Equal(t, []string{"  - a", "  - b", "  - c"}, v.Text())
}

func TestValue_Text_SliceNegated(t *testing.T) {
	v := NewValue([]any{"a", "b"})
	v.Negate()
	assert.Equal(t, []string{"not", "  - a", "  - b"}, v.Text())
}

func TestValue_Text_MapDefault(t *testing.T) {
	v := NewValue(map[string]any{"key": "val"})
	assert.Equal(t, []string{"  key: val"}, v.Text())
}

func TestValue_Text_MapNegated(t *testing.T) {
	v := NewValue(map[string]any{"key": "val"})
	v.Negate()
	result := v.Text()
	assert.Len(t, result, 2)
	assert.Equal(t, "not", result[0])
	assert.Equal(t, "  key: val", result[1])
}

func TestValue_DoubleNegate_RestoresOriginal(t *testing.T) {
	v := NewValue("test")
	v.Negate()
	v.Negate()
	assert.False(t, v.Negated())
	assert.Equal(t, []string{"test"}, v.Text())
}

// mockTexter implements the Texter interface for testing Value with Texter values.
type mockTexter struct {
	texts []string
}

func (m *mockTexter) Text() []string {
	return m.texts
}

func TestValue_Text_TexterDefault(t *testing.T) {
	v := NewValue(&mockTexter{texts: []string{"line1", "line2"}})
	assert.Equal(t, []string{"  line1", "  line2"}, v.Text())
}

func TestValue_Text_TexterNegated(t *testing.T) {
	v := NewValue(&mockTexter{texts: []string{"line1"}})
	v.Negate()
	assert.Equal(t, []string{"not", "  line1"}, v.Text())
}

func TestValue_Text_EmptySlice(t *testing.T) {
	v := NewValue([]any{})
	assert.Equal(t, []string{}, v.Text())
}

func TestValue_Text_EmptyMap(t *testing.T) {
	v := NewValue(map[string]any{})
	assert.Equal(t, []string{}, v.Text())
}

func TestValue_Text_NilValue(t *testing.T) {
	v := NewValue(nil)
	assert.Equal(t, []string{"<nil>"}, v.Text())
}

func TestValue_Text_NilValueNegated(t *testing.T) {
	v := NewValue(nil)
	v.Negate()
	assert.Equal(t, []string{"not <nil>"}, v.Text())
}

// --- Interface compliance ---

func TestEqual_ImplementsItemWithPath(t *testing.T) {
	var _ ItemWithPath = NewEqual()
}

func TestNotEqual_ImplementsItemWithPath(t *testing.T) {
	var _ ItemWithPath = NewNotEqual()
}

func TestGreater_ImplementsItemWithPath(t *testing.T) {
	var _ ItemWithPath = NewGreater()
}

func TestLess_ImplementsItemWithPath(t *testing.T) {
	var _ ItemWithPath = NewLess()
}

func TestGreaterOrEqual_ImplementsItemWithPath(t *testing.T) {
	var _ ItemWithPath = NewGreaterOrEqual()
}

func TestLessOrEqual_ImplementsItemWithPath(t *testing.T) {
	var _ ItemWithPath = NewLessOrEqual()
}

func TestBlank_ImplementsItem(t *testing.T) {
	var _ Item = NewBlank()
}

func TestTrue_ImplementsItem(t *testing.T) {
	var _ Item = NewTrue()
}

func TestFalse_ImplementsItem(t *testing.T) {
	var _ Item = NewFalse()
}

func TestValue_ImplementsItem(t *testing.T) {
	var _ Item = NewValue("x")
}
