package common

import (
	"github.com/threagile/threagile/pkg/security/types"
	"gopkg.in/yaml.v3"
	"strings"
)

type Scope struct {
	Parent      *Scope
	Args        []Value
	Vars        map[string]Value
	Model       map[string]any
	Risk        map[string]any
	Methods     map[string]Statement
	item        Value
	returnValue Value
}

func (what *Scope) Init(risk *types.RiskCategory, methods map[string]Statement) error {
	if risk != nil {
		data, marshalError := yaml.Marshal(risk)
		if marshalError != nil {
			return marshalError
		}

		unmarshalError := yaml.Unmarshal(data, &what.Risk)
		if unmarshalError != nil {
			return unmarshalError
		}
	}

	what.Methods = methods

	return nil
}

func (what *Scope) SetModel(model *types.Model) error {
	if model != nil {
		data, marshalError := yaml.Marshal(model)
		if marshalError != nil {
			return marshalError
		}

		unmarshalError := yaml.Unmarshal(data, &what.Model)
		if unmarshalError != nil {
			return unmarshalError
		}
	}

	return nil
}

func (what *Scope) Clone() (*Scope, error) {
	varsCopy, copyError := Values(what.Vars).Copy()
	if copyError != nil {
		return what, copyError
	}

	scope := Scope{
		Parent:  what,
		Model:   what.Model,
		Risk:    what.Risk,
		Methods: what.Methods,
		Vars:    varsCopy,
	}

	return &scope, nil
}

func (what *Scope) Set(name string, value Value) {
	if what.Vars == nil {
		what.Vars = make(map[string]Value)
	}

	what.Vars[name] = value
}

func (what *Scope) Get(name string) (Value, bool) {
	path := strings.Split(name, ".")
	if strings.HasPrefix(path[0], "$") {
		switch strings.ToLower(path[0]) {
		case "$model":
			value, ok := what.get(path[1:], what.Model)
			if ok {
				return SomeValue(value, NewHistory(name)), true
			}

		case "$risk":
			value, ok := what.get(path[1:], what.Risk)
			if ok {
				return SomeValue(value, NewHistory(name)), true
			}
		}
	}

	if len(path[0]) == 0 {
		if len(path[1:]) > 0 {
			if what.item == nil {
				return SomeValue(nil, NewHistory(name)), false
			}

			switch castValue := what.item.Value().(type) {
			case map[string]any:
				value, ok := what.get(path[1:], castValue)
				if ok {
					return SomeValue(value, NewHistory(name)), true
				}

			default:
				return SomeValue(nil, NewHistory(name)), false
			}
		} else {
			return what.item, true
		}
	}

	value, ok := what.getVar(path)
	if ok {
		return SomeValue(value.Value(), NewHistory(name).From(value.History())), true
	}

	if what.Parent != nil {
		return what.Parent.Get(name)
	}

	return SomeValue(value, NewHistory(name)), false
}

func (what *Scope) GetItem() Value {
	return what.item
}

func (what *Scope) SetItem(value Value) Value {
	what.item = value
	return value
}

func (what *Scope) PopItem() Value {
	var currentItem Value
	currentItem, what.item = what.item, nil
	return currentItem
}

func (what *Scope) SetReturnValue(value Value) {
	what.returnValue = value
}

func (what *Scope) GetReturnValue() Value {
	return what.returnValue
}

func (what *Scope) get(path []string, item map[string]any) (Value, bool) {
	if len(path) == 0 {
		return NilValue(), false
	}

	if item == nil {
		return NilValue(), false
	}

	field, ok := item[strings.ToLower(path[0])]
	if !ok {
		return NilValue(), false
	}

	if len(path) == 1 {
		switch castField := field.(type) {
		case Value:
			return SomeValue(castField.Value(), NewHistory(path[0]).From(castField.History())), true

		default:
			return SomeValue(field, NewHistory(path[0])), true
		}
	}

	value, isMap := field.(map[string]any)
	if !isMap {
		return NilValue(), false
	}

	return what.get(path[1:], value)
}

func (what *Scope) getVar(path []string) (Value, bool) {
	if len(path) == 0 {
		return nil, false
	}

	if what.Vars == nil {
		return nil, false
	}

	var field Value
	if len(path[0]) == 0 {
		if what.item == nil {
			return nil, false
		}

		field = what.item
	} else {
		var fieldOk bool
		field, fieldOk = what.Vars[strings.ToLower(path[0])]
		if !fieldOk {
			return nil, false
		}
	}

	if len(path) == 1 {
		return field, true
	}

	value, isMap := field.Value().(map[string]any)
	if !isMap {
		return nil, false
	}

	return what.get(path[1:], value)
}
