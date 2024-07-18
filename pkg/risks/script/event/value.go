package event

type Value interface {
	Path() Path        // origin path
	ValueText() Text   // text representation of value
	History() History  // events resulting in this value
	Text() Text        // origin path if present, value text otherwise
	Description() Text // description, including origin path and value
}
