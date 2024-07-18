package event

type Greater struct {
	negated bool
	item1   Value
	item2   Value
	history History
}

func NewGreater(item1 Value, item2 Value, history ...Event) *Greater {
	return &Greater{
		item1:   item1,
		item2:   item2,
		history: history,
	}
}

func (what *Greater) Negate() Event {
	what.negated = !what.negated
	return what
}

func (what *Greater) Text() Text {
	if len(what.item1.Path()) == 0 && len(what.item2.Path()) == 0 {
		return append(what.history, append(what.item1.History(), what.item2.History()...)...).Text()
	}

	if what.negated {
		return makeTwoValueText(what.item1, "is less than or equal to", what.item2)
	}

	return makeTwoValueText(what.item1, "is greater than", what.item2)
}

func (what *Greater) History() History {
	return what.history
}
