package event

type Less struct {
	negated bool
	item1   Value
	item2   Value
	history History
}

func NewLess(item1 Value, item2 Value, history ...Event) *Less {
	return &Less{
		item1:   item1,
		item2:   item2,
		history: history,
	}
}

func (what *Less) Negate() Event {
	what.negated = !what.negated
	return what
}

func (what *Less) Text() Text {
	if len(what.item1.Path()) == 0 && len(what.item2.Path()) == 0 {
		return append(what.history, append(what.item1.History(), what.item2.History()...)...).Text()
	}

	if what.negated {
		return makeTwoValueText(what.item1, "is greater than or equal to", what.item2)
	}

	return makeTwoValueText(what.item1, "is less than", what.item2)
}

func (what *Less) History() History {
	return what.history
}
