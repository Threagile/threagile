package event

type LessOrEqual struct {
	negated bool
	item1   Value
	item2   Value
	history History
}

func NewLessOrEqual(item1 Value, item2 Value, history ...Event) *LessOrEqual {
	return &LessOrEqual{
		item1:   item1,
		item2:   item2,
		history: history,
	}
}

func (what *LessOrEqual) Negate() Event {
	what.negated = !what.negated
	return what
}

func (what *LessOrEqual) Text() Text {
	if len(what.item1.Path()) == 0 && len(what.item2.Path()) == 0 {
		return append(what.history, append(what.item1.History(), what.item2.History()...)...).Text()
	}

	if what.negated {
		return makeTwoValueText(what.item1, "is greater than", what.item2)
	}

	return makeTwoValueText(what.item1, "is less than or equal to", what.item2)
}

func (what *LessOrEqual) History() History {
	return what.history
}
