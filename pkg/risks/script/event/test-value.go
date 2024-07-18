package event

import "fmt"

type TestValue struct {
	value   any
	path    Path
	history History
}

func NewTestValue(value any, path Path, history ...Event) *TestValue {
	return &TestValue{
		value:   value,
		path:    path,
		history: history,
	}
}

func (what TestValue) Value() any {
	return what.value
}

func (what TestValue) Path() Path {
	return what.path
}

func (what TestValue) ValueText() Text {
	return new(Text).Append(fmt.Sprintf("%v", what.value))
}

func (what TestValue) History() History {
	return what.history
}

func (what TestValue) Text() Text {
	if len(what.path) > 0 {
		return new(Text).Append(what.path.String())
	}

	return what.ValueText()
}

func (what TestValue) Description() Text {
	return new(Text).Append(fmt.Sprintf("%v is %v", what.path.String(), what.value))
}
