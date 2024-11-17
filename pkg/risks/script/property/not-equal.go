package property

type NotEqual struct {
	negated bool
}

func NewNotEqual() *NotEqual {
	return new(NotEqual)
}

func (what *NotEqual) Path() {
}

func (what *NotEqual) Negate() {
	what.negated = !what.negated
}

func (what *NotEqual) Negated() bool {
	return what.negated
}

func (what *NotEqual) Text() []string {
	if what.negated {
		return []string{"equal to"}
	}

	return []string{"not equal to"}
}
