package event

type Event interface {
	Negate() Event
	Text() Text
	History() History
}
