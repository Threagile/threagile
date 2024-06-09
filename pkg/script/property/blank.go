package property

/*
	this is a property for a value that should not be printed as part of the history, such as structured values
*/

type Blank struct {
}

func NewBlank() *Blank {
	return new(Blank)
}

func (what *Blank) Negate() {
}

func (what *Blank) Negated() bool {
	return false
}

func (what *Blank) Text() []string {
	return []string{}
}
