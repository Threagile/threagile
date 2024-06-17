package common

import (
	"github.com/threagile/threagile/pkg/types"
	"gopkg.in/yaml.v3"
	"strings"
)

type Scope struct {
	Parent      *Scope
	Category    *types.RiskCategory
	Args        []Value
	Vars        map[string]Value
	Model       map[string]any
	Risk        map[string]any
	Methods     map[string]Statement
	Deferred    []Statement
	Explain     ExplainStatement
	CallStack   History
	HasReturned bool
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

	what.Category = risk
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
		Parent:    what,
		Category:  what.Category,
		Args:      what.Args,
		Vars:      varsCopy,
		Model:     what.Model,
		Risk:      what.Risk,
		Methods:   what.Methods,
		CallStack: what.CallStack,
	}

	return &scope, nil
}

func (what *Scope) Defer(statement Statement) {
	what.Deferred = append(what.Deferred, statement)
}

func (what *Scope) PushCall(event *Event) History {
	what.CallStack = what.CallStack.New(event)
	return what.CallStack
}

func (what *Scope) PopCall() {
	if len(what.CallStack) > 0 {
		what.CallStack = what.CallStack[:len(what.CallStack)-1]
	}
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
		// value name starts with `$model`: refers to `what.Model`
		case "$model":
			value, ok := what.get(path[1:], what.Model, NewPath("threat model", strings.Join(path[1:], ".")))
			if ok {
				return value, true
			}

		// value name starts with `$risk`: refers to `what.Risk`
		case "$risk":
			value, ok := what.get(path[1:], what.Risk, NewPath("risk category", strings.Join(path[1:], ".")))
			if ok {
				return value, true
			}
		}
	}

	// value name starts with a dot: refers to `what.item`
	if len(path[0]) == 0 {
		if len(path[1:]) > 0 {
			if what.item == nil {
				return nil, false
			}

			switch castValue := what.item.Value().(type) {
			case map[string]any:
				value, ok := what.get(path[1:], castValue, what.item.Event().Path().Copy().AddPathLeaf(strings.Join(path[1:], ".")))
				if ok {
					return value, true
				}
			}

			return nil, false
		}

		return what.item, true
	}

	// value name starts with something else: refers to `what.Vars`
	if what.Vars == nil {
		return nil, false
	}

	variable, fieldOk := what.Vars[strings.ToLower(path[0])]
	if !fieldOk {
		return nil, false
	}

	if len(path) == 1 {
		return variable, true
	}

	value, isMap := variable.Value().(map[string]any)
	if isMap {
		return what.get(path[1:], value, variable.Event().Path().Copy().AddPathLeaf(strings.Join(path[1:], ".")))
	}

	// value name does not resolve
	return nil, false
}

func (what *Scope) GetHistory() []*Event {
	history := make([]*Event, 0)
	for _, event := range what.CallStack {
		newHistory := what.getHistory(event)
		if newHistory != nil {
			history = append(history, newHistory...)
		}
	}

	return history
}

func (what *Scope) getHistory(event *Event) []*Event {
	history := make([]*Event, 0)
	if event == nil {
		return history
	}

	if event.Origin != nil && len(event.Origin.Path) > 0 {
		return append(history, event)
	}

	for _, subEvent := range event.Events {
		newHistory := what.getHistory(subEvent)
		if newHistory != nil {
			history = append(history, newHistory...)
		}
	}

	return history
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

func (what *Scope) get(path []string, item map[string]any, valuePath *Path) (Value, bool) {
	if len(path) == 0 {
		return nil, false
	}

	if item == nil {
		return nil, false
	}

	field, ok := item[strings.ToLower(path[0])]
	if !ok {
		return SomeValue(nil, NewEvent(NewValueProperty(nil), valuePath)), false
	}

	if len(path) == 1 {
		switch castField := field.(type) {
		case Value:
			return castField, true

		default:
			return SomeValue(castField, NewEvent(NewValueProperty(castField), valuePath)), true
		}
	}

	value, isMap := field.(map[string]any)
	if isMap {
		return what.get(path[1:], value, valuePath)
	}

	return nil, false
}
