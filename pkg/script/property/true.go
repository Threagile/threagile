package property

type True struct {
	negated bool
}

func NewTrue() *True {
	return new(True)
}

func (what *True) Negate() {
	what.negated = !what.negated
}

func (what *True) Negated() bool {
	return what.negated
}

func (what *True) Text() []string {
	if what.negated {
		return []string{"false"}
	}

	return []string{"true"}
}
