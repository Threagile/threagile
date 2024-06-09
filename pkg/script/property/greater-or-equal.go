package property

type GreaterOrEqual struct {
	negated bool
}

func NewGreaterOrEqual() *GreaterOrEqual {
	return new(GreaterOrEqual)
}

func (what *GreaterOrEqual) Path() {
}

func (what *GreaterOrEqual) Negate() {
	what.negated = !what.negated
}

func (what *GreaterOrEqual) Negated() bool {
	return what.negated
}

func (what *GreaterOrEqual) Text() []string {
	if what.negated {
		return []string{"less than"}
	}

	return []string{"greater than or equal to"}
}
