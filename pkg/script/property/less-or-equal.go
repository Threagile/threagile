package property

type LessOrEqual struct {
	negated bool
}

func NewLessOrEqual() *LessOrEqual {
	return new(LessOrEqual)
}

func (what *LessOrEqual) Path() {
}

func (what *LessOrEqual) Negate() {
	what.negated = !what.negated
}

func (what *LessOrEqual) Negated() bool {
	return what.negated
}

func (what *LessOrEqual) Text() []string {
	if what.negated {
		return []string{"greater than"}
	}

	return []string{"less than or equal to"}
}
