package event

type ValueEvent struct {
	negated bool
	item    Value
}

func NewValueEvent(item Value) *ValueEvent {
	return &ValueEvent{
		item: item,
	}
}

func (what *ValueEvent) Negate() Event {
	what.negated = !what.negated
	return what
}

func (what *ValueEvent) Text() Text {
	return what.item.Description()
}

func (what *ValueEvent) History() History {
	return nil
}
