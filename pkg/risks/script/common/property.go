package common

import (
	"fmt"
	"github.com/threagile/threagile/pkg/risks/script/property"
)

type Property struct {
	Property property.Item
	Path     *Path
}

func NewBlankProperty() *Property {
	return &Property{
		Property: property.NewBlank(),
	}
}

func NewEqualProperty(value Value) *Property {
	var path *Path
	if value.Event() != nil {
		path = value.Event().Path().Copy()
	}

	return &Property{
		Property: property.NewEqual(),
		Path:     path,
	}
}

func NewFalseProperty() *Property {
	return &Property{
		Property: property.NewFalse(),
	}
}

func NewGreaterProperty(value Value) *Property {
	var path *Path
	if value.Event() != nil {
		path = value.Event().Path().Copy()
	}

	return &Property{
		Property: property.NewGreater(),
		Path:     path,
	}
}

func NewLessProperty(value Value) *Property {
	var path *Path
	if value.Event() != nil {
		path = value.Event().Path().Copy()
	}

	return &Property{
		Property: property.NewLess(),
		Path:     path,
	}
}

func NewNotEqualProperty(value Value) *Property {
	var path *Path
	if value.Event() != nil {
		path = value.Event().Path().Copy()
	}

	return &Property{
		Property: property.NewNotEqual(),
		Path:     path,
	}
}

func NewTrueProperty() *Property {
	return &Property{
		Property: property.NewTrue(),
	}
}

func NewValueProperty(value any) *Property {
	return &Property{
		Property: property.NewValue(value),
	}
}

func (what *Property) Text() []string {
	if what == nil {
		return []string{}
	}

	propertyText := what.Property.Text()
	switch len(propertyText) {
	case 0: // blank
		return []string{}

	case 1:
		if what.Path != nil {
			return []string{fmt.Sprintf("%v %v", propertyText[0], what.Path.String())}
		}

		return propertyText

	default: // value property
		return propertyText
	}
}

func (what *Property) SetPath(path *Path) *Property {
	if what == nil {
		return what
	}

	what.Path = path
	return what
}

func (what *Property) AddPathParent(path ...string) *Property {
	if what == nil {
		return what
	}

	what.Path.AddPathParent(path...)
	return what
}

func (what *Property) AddPathLeaf(path ...string) *Property {
	if what == nil {
		return what
	}

	what.Path.AddPathLeaf(path...)
	return what
}
