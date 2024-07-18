package common

/*
type Event struct {
	Event property.Event
	Path     Path
}

func NewEqualProperty(value Value) *Event {
	var path Path
	if value.EventX() != nil {
		path = *value.EventX().Path().Copy()
	}

	return &Event{
		Event: property.NewEqual(),
		Path:     path,
	}
}

func NewFalseProperty() *Event {
	return &Event{
		Event: property.NewFalse(),
	}
}

func NewGreaterProperty(value Value) *Event {
	var path Path
	if value.EventX() != nil {
		path = *value.EventX().Path().Copy()
	}

	return &Event{
		Event: property.NewGreater(),
		Path:     path,
	}
}

func NewLessProperty(value Value) *Event {
	var path Path
	if value.EventX() != nil {
		path = *value.EventX().Path().Copy()
	}

	return &Event{
		Event: property.NewLess(),
		Path:     path,
	}
}

func NewNotEqualProperty(value Value) *Event {
	var path Path
	if value.EventX() != nil {
		path = *value.EventX().Path().Copy()
	}

	return &Event{
		Event: property.NewNotEqual(),
		Path:     path,
	}
}

func NewTrueProperty() *Event {
	return &Event{
		Event: property.NewTrue(),
	}
}

func NewValueProperty(value any) *Event {
	return &Event{
		Event: property.NewValue(value),
	}
}

func (what *Event) ValueText() []string {
	if what == nil {
		return []string{}
	}

	originalPropertyText := what.Event.ValueText()
	propertyText := make([]string, 0)
	for _, text := range originalPropertyText {
		if len(text) > 0 {
			propertyText = append(propertyText, text)
		}
	}

	switch len(propertyText) {
	case 0: // blank
		return []string{}

	case 1:
		if what.Path != nil {
			return []string{fmt.Sprintf("%v %v", propertyText[0], what.Path.String())}
		}

		return propertyText

	default: // value property
		return propertyText
	}
}

func (what *Event) SetPath(path Path) *Event {
	if what == nil {
		return what
	}

	what.Path = path
	return what
}

func (what *Event) AddPathParent(path ...string) *Event {
	if what == nil {
		return what
	}

	what.Path.AddParent(path...)
	return what
}

func (what *Event) AddPathLeaf(path ...string) *Event {
	if what == nil {
		return what
	}

	what.Path.AddLeaf(path...)
	return what
}
*/
