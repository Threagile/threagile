package event

type False struct {
	negated bool
	item    Value
	history History
}

func NewFalse(item Value, history ...Event) *False {
	return &False{
		item:    item,
		history: history,
	}
}

func (what *False) Negate() Event {
	what.negated = !what.negated
	return what
}

func (what *False) Text() Text {
	if len(what.item.Path()) == 0 {
		return append(what.history, what.item.History()...).Text()
	}

	if what.negated {
		return makeOneValueText(what.item, "is true")
	}

	return makeOneValueText(what.item, "is false")
}

func (what *False) History() History {
	return what.history
}
