package common

import (
	"encoding/json"
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
	iterator    Value
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
		data, marshalError := json.Marshal(model)
		if marshalError != nil {
			return marshalError
		}

		unmarshalError := json.Unmarshal(data, &what.Model)
		if unmarshalError != nil {
			return unmarshalError
		}
	}

	return nil
}

func (what *Scope) Clone() (*Scope, error) {
	data, marshalError := json.Marshal(what.Vars)
	if marshalError != nil {
		return nil, marshalError
	}

	scope := Scope{
		Parent:  what,
		Model:   what.Model,
		Risk:    what.Risk,
		Methods: what.Methods,
	}

	unmarshalError := json.Unmarshal(data, &scope.Vars)
	if unmarshalError != nil {
		return nil, unmarshalError
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
	if strings.HasPrefix(name, "$") {
		switch strings.ToLower(path[0]) {
		case "$model":
			value, ok := what.get(path[1:], what.Model)
			if ok {
				return value, true
			}

		case "$risk":
			value, ok := what.get(path[1:], what.Risk)
			if ok {
				return value, true
			}
		}
	}

	value, ok := what.getVar(path)
	if ok {
		return value, true
	}

	if what.Parent != nil {
		return what.Parent.Get(name)
	}

	return nil, false
}

func (what *Scope) GetIterator() Value {
	return what.iterator
}

func (what *Scope) SetIterator(value Value) {
	what.iterator = value
}

func (what *Scope) SwapIterator(value Value) Value {
	var currentIterator Value
	currentIterator, what.iterator = what.iterator, value
	return currentIterator
}

func (what *Scope) SetReturnValue(value Value) {
	what.returnValue = value
}

func (what *Scope) GetReturnValue() Value {
	return what.returnValue
}

func (what *Scope) get(path []string, item map[string]any) (Value, bool) {
	if len(path) == 0 {
		return nil, false
	}

	if item == nil {
		return nil, false
	}

	field, ok := item[strings.ToLower(path[0])]
	if !ok {
		return nil, false
	}

	if len(path) == 1 {
		return field, true
	}

	value, isMap := field.(map[string]any)
	if !isMap {
		return nil, false
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
		field = what.iterator
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

	value, isMap := field.(map[string]any)
	if !isMap {
		return nil, false
	}

	return what.get(path[1:], value)
}
