package property

type Greater struct {
	negated bool
}

func NewGreater() *Greater {
	return new(Greater)
}

func (what *Greater) Path() {
}

func (what *Greater) Negate() {
	what.negated = !what.negated
}

func (what *Greater) Negated() bool {
	return what.negated
}

func (what *Greater) Text() []string {
	if what.negated {
		return []string{"less than or equal to"}
	}

	return []string{"greater than"}
}
