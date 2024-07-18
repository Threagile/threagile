package event

type History []Event

func (what History) Text() Text {
	lines := make(Text, 0)
	for _, item := range what {
		lines = append(lines, item.Text()...)
	}

	return lines
}
