package common

import (
	"strings"
)

type Event struct {
	Origin   *Path
	Property *Property
	Events   []*Event
}

func NewEvent(property *Property, path *Path) *Event {
	return &Event{
		Property: property,
		Origin:   path,
	}
}

func NewEventFrom(property *Property, firstValue Value, value ...Value) *Event {
	var path *Path
	var events []*Event
	if firstValue != nil && firstValue.Event() != nil {
		path = firstValue.Event().Path().Copy()
		events = firstValue.Event().Events
	}

	event := &Event{
		Property: property,
		Origin:   path,
		Events:   events,
	}

	event.From(value...)

	return event
}

func EmptyEvent() *Event {
	return &Event{
		Property: NewBlankProperty(),
	}
}

func (what *Event) From(values ...Value) *Event {
	if what == nil {
		return what
	}

	for _, value := range values {
		if value.Event() != nil {
			what.Events = append(what.Events, value.Event())
		}
	}
	return what
}

func (what *Event) AddHistory(history []*Event) *Event {
	if what == nil {
		return what
	}

	for _, event := range history {
		what.Events = append(what.Events, event)
	}

	return what
}

func (what *Event) Path() *Path {
	if what == nil {
		return nil
	}

	return what.Origin
}

func (what *Event) SetPath(path *Path) *Event {
	if what == nil {
		return what
	}

	what.Origin = path
	return what
}

func (what *Event) AddPathParent(path ...string) *Event {
	if what == nil {
		return what
	}

	what.Origin.AddPathParent(path...)
	return what
}

func (what *Event) AddPathLeaf(path ...string) *Event {
	if what == nil {
		return what
	}

	what.Origin.AddPathLeaf(path...)
	return what
}

func (what *Event) String() string {
	if what == nil {
		return ""
	}

	return strings.Join(what.Indented(0), "\n")
}

func (what *Event) Indented(level int) []string {
	if what == nil {
		return []string{}
	}

	propertyText := what.Property.Text()

	lines := make([]string, 0)
	text := what.Origin.String() + " is "
	if len(propertyText) <= 1 {
		text += strings.Join(propertyText, " ")

		if len(what.Events) > 0 {
			text += " because"
		}

		if len(text) > 0 {
			lines = append(lines, what.indent(level, text))
		}
	} else {
		for _, line := range propertyText {
			lines = append(lines, what.indent(level+1, line))
		}

		if len(what.Events) > 0 {
			lines = append(lines, what.indent(level, " because"))
		}
	}

	for _, event := range what.Events {
		lines = append(lines, event.Indented(level+1)...)
	}

	return lines
}

func (what *Event) indent(level int, text string) string {
	if what == nil {
		return ""
	}

	return strings.Repeat("    ", level) + text
}
