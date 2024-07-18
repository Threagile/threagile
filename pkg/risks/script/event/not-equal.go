package event

type NotEqual struct {
	negated bool
	item1   Value
	item2   Value
	history History
}

func NewNotEqual(item1 Value, item2 Value, history ...Event) *NotEqual {
	return &NotEqual{
		item1:   item1,
		item2:   item2,
		history: history,
	}
}

func (what *NotEqual) Negate() Event {
	what.negated = !what.negated
	return what
}

func (what *NotEqual) Text() Text {
	if len(what.item1.Path()) == 0 && len(what.item2.Path()) == 0 {
		return append(what.history, append(what.item1.History(), what.item2.History()...)...).Text()
	}

	if what.negated {
		return makeTwoValueText(what.item1, "is equal to", what.item2)
	}

	return makeTwoValueText(what.item1, "is not equal to", what.item2)
}

func (what *NotEqual) History() History {
	return what.history
}
