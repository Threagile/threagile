package property

type Equal struct {
	negated bool
}

func NewEqual() *Equal {
	return new(Equal)
}

func (what *Equal) Path() {
}

func (what *Equal) Negate() {
	what.negated = !what.negated
}

func (what *Equal) Negated() bool {
	return what.negated
}

func (what *Equal) Text() []string {
	if what.negated {
		return []string{"not equal to"}
	}

	return []string{"equal to"}
}
