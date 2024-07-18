package event

const (
	INDENT = "  "
)

type Texter interface {
	Text() Text
}
