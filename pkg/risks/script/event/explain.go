package event

type Explain struct {
	negated bool
	text    string
	history History
}

func NewExplain(text string, history ...Event) *Explain {
	return &Explain{
		text:    text,
		history: history,
	}
}

func (what *Explain) Negate() Event {
	what.negated = !what.negated
	return what
}

func (what *Explain) Text() Text {
	return new(Text).Append(what.text)
}

func (what *Explain) History() History {
	return what.history
}
