package property

type False struct {
	negated bool
}

func NewFalse() *False {
	return new(False)
}

func (what *False) Value() any {
	return what.negated
}

func (what *False) Negate() {
	what.negated = !what.negated
}

func (what *False) Negated() bool {
	return what.negated
}

func (what *False) Text() []string {
	if what.negated {
		return []string{"true"}
	}

	return []string{"false"}
}
