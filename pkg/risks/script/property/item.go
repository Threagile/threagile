package property

type Item interface {
	Negate()
	Negated() bool
	Text() []string
}
