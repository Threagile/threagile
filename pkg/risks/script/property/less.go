package property

type Less struct {
	negated bool
}

func NewLess() *Less {
	return new(Less)
}

func (what *Less) Path() {
}

func (what *Less) Negate() {
	what.negated = !what.negated
}

func (what *Less) Negated() bool {
	return what.negated
}

func (what *Less) Text() []string {
	if what.negated {
		return []string{"greater than or equal to"}
	}

	return []string{"less than"}
}
