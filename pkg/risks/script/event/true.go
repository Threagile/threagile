package event

type True struct {
	negated bool
	item    Value
	history History
}

func NewTrue(item Value, history ...Event) *True {
	return &True{
		item:    item,
		history: history,
	}
}

func (what *True) Negate() Event {
	what.negated = !what.negated
	return what
}

func (what *True) Text() Text {
	if len(what.item.Path()) == 0 {
		return append(what.history, what.item.History()...).Text()
	}

	if what.negated {
		return makeOneValueText(what.item, "is false")
	}

	return makeOneValueText(what.item, "is true")
}

func (what *True) History() History {
	return what.history
}
