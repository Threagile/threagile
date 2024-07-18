package event

type Contain struct {
	negated bool
	set     Value
	item    Value
	history History
}

func NewContain(set Value, item Value, history ...Event) *Contain {
	return &Contain{
		set:     set,
		item:    item,
		history: history,
	}
}

func (what *Contain) Negate() Event {
	what.negated = !what.negated
	return what
}

func (what *Contain) Text() Text {
	if len(what.set.Path()) == 0 && len(what.item.Path()) == 0 {
		return append(what.history, append(what.set.History(), what.item.History()...)...).Text()
	}

	if what.negated {
		return makeTwoValueText(what.set, "does not contain", what.item)
	}

	return makeTwoValueText(what.set, "contains", what.item)
}

func (what *Contain) History() History {
	return what.history
}
