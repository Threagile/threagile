package common

import (
	"fmt"
	"strings"
)

type History []HistoryItem

type HistoryItem struct {
	Text    string
	History []History
}

func NewHistory(format string, a ...any) History {
	return new(History).New(format, a...)
}

func (what History) New(format string, a ...any) History {
	history := what
	if history == nil {
		history = make(History, 0)
	}

	return append(history, HistoryItem{
		Text: fmt.Sprintf(format, a...),
	})
}

func (what History) From(histories ...History) History {
	history := what
	if history == nil {
		history = make(History, 0)
	}

	var item HistoryItem
	if len(history) > 0 {
		item, history = history[0], history[1:]
	}

	item.History = append(item.History, histories...)
	return append(history, item)
}

func (what History) String() string {
	return strings.Join(what.Indented(0), "\n")
}

func (what History) Indented(level int) []string {
	lines := make([]string, 0)
	for _, historyItem := range what {
		lines = append(lines, historyItem.Indented(level)...)
	}

	return lines
}

func (what HistoryItem) Indented(level int) []string {
	lines := make([]string, 0)
	lines = append(lines, what.indent(level, what.Text))

	for _, history := range what.History {
		lines = append(lines, history.Indented(level+1)...)
	}

	return lines
}

func (what HistoryItem) indent(level int, text string) string {
	return strings.Repeat("    ", level) + text
}
