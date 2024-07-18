package event

type Equal struct {
	negated bool
	item1   Value
	item2   Value
	history History
}

func NewEqual(item1 Value, item2 Value, history ...Event) *Equal {
	return &Equal{
		item1:   item1,
		item2:   item2,
		history: history,
	}
}

func (what *Equal) Negate() Event {
	what.negated = !what.negated
	return what
}

func (what *Equal) Text() Text {
	if len(what.item1.Path()) == 0 && len(what.item2.Path()) == 0 {
		return append(what.history, append(what.item1.History(), what.item2.History()...)...).Text()
	}

	if what.negated {
		return makeTwoValueText(what.item1, "is not equal to", what.item2)
	}

	return makeTwoValueText(what.item1, "is equal to", what.item2)
}

func (what *Equal) History() History {
	return what.history
}
