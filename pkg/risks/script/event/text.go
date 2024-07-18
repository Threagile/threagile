package event

import (
	"strings"
)

type Text []TextItem

type TextItem struct {
	Line    string
	SubText Text
}

func (what Text) Append(line string, items ...TextItem) Text {
	return append(what, TextItem{Line: line, SubText: items})
}

func (what Text) Lines() []string {
	text := make([]string, 0)
	for _, item := range what {
		line := item.Line

		switch len(item.SubText) {
		case 0:
			text = append(text, line)

		default:
			text = append(text, line+" because")
			text = append(text, indent(item.SubText.Lines())...)
		}
	}

	return text
}

func (what Text) Indent(lines []string) []string {
	return indent(lines)
}

func (what Text) String() string {
	return strings.Join(what.Lines(), "\n")
}

func makeOneValueText(value Value, verbText string) Text {
	if value == nil {
		return new(Text).Append("nil " + verbText)
	}

	text := value.Text()
	switch len(text) {
	case 0:
		return new(Text).Append("(empty) "+verbText, value.History().Text()...)

	case 1:
		return new(Text).Append(text[0].Line+" "+verbText, value.History().Text()...)

	default:
		return text.Append(verbText, value.History().Text()...)
	}
}

func makeTwoValueText(value1 Value, verbText string, value2 Value) Text {
	switch value1.(type) {
	case nil:
		switch value2.(type) {
		case nil:
			return new(Text).Append("nil " + verbText + " nil")

		default:
			text2 := value2.Text()
			switch len(text2) {
			case 0:
				text2 = new(Text).Append("nil "+verbText+" (empty)", value2.History().Text()...)

			case 1:
				text2 = new(Text).Append("nil "+verbText+" "+text2[0].Line, value2.History().Text()...)

			default:
				text2 = append(new(Text).Append("nil "+verbText), text2...)
				text2[len(text2)-1].SubText = value2.History().Text()
			}

			return text2
		}
	}

	switch value2.(type) {
	case nil:
		text1 := value1.Text()
		switch len(text1) {
		case 0:
			text1 = new(Text).Append("(empty) "+verbText+" nil", value1.History().Text()...)

		case 1:
			text1 = new(Text).Append(text1[0].Line+" "+verbText+" nil", value1.History().Text()...)

		default:
			return text1.Append(verbText+" nil", value1.History().Text()...)
		}

		return text1
	}

	text1 := value1.Text()
	text2 := value2.Text()
	switch len(text1) {
	case 0:
		switch len(text2) {
		case 0:
			text2 = new(Text).Append("(empty) "+verbText+" (empty)", append(value1.History().Text(), value2.History().Text()...)...)

		case 1:
			text2 = new(Text).Append("(empty) "+verbText+" "+text2[0].Line, append(value1.History().Text(), value2.History().Text()...)...)

		default:
			text2 = append(new(Text).Append("(empty) "+verbText), text2...)
			text2[len(text2)-1].SubText = append(value1.History().Text(), value2.History().Text()...)
		}

		return text2

	case 1:
		switch len(text2) {
		case 0:
			text2 = new(Text).Append(text1[0].Line+" "+verbText+" (empty)", append(value1.History().Text(), value2.History().Text()...)...)

		case 1:
			text2 = new(Text).Append(text1[0].Line+" "+verbText+" "+text2[0].Line, append(value1.History().Text(), value2.History().Text()...)...)

		default:
			text2 = append(new(Text).Append(text1[0].Line+" "+verbText), text2...)
			text2[len(text2)-1].SubText = append(value1.History().Text(), value2.History().Text()...)
		}

		return text2

	default:
		switch len(text2) {
		case 0:
			text2 = text1.Append(verbText+" (empty)", append(value1.History().Text(), value2.History().Text()...)...)

		case 1:
			text2 = text1.Append(verbText+" "+text2[0].Line, append(value1.History().Text(), value2.History().Text()...)...)

		default:
			text2 = append(text1.Append(verbText), text2...)
			text2[len(text2)-1].SubText = append(value1.History().Text(), value2.History().Text()...)
		}

		return text2
	}
}

func GetLines(text string) []string {
	value := strings.ReplaceAll(text, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\n\r", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")

	return strings.Split(value, "\n")
}

func IndentAndConcatenate(text []string) []string {
	return indent(makeList(text))
}

func indent(text []string) []string {
	newText := make([]string, 0)
	for _, line := range text {
		newText = append(newText, INDENT+line)
	}

	return newText
}

func makeList(text []string) []string {
	newText := make([]string, 0)
	for n, line := range text {
		if n < len(text)-1 {
			line += ", and"
		}

		newText = append(newText, line)
	}

	return newText
}
