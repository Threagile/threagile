package common

import "fmt"

type Values map[string]Value

func (what Values) Copy() (Values, error) {
	values := make(Values, 0)
	for name, value := range what {
		switch castValue := value.(type) {
		case *AnyValue:
			values[name] = SomeValueWithPath(castValue.Value(), castValue.Path(), nil, castValue.History()...)

		case *ArrayValue:
			values[name] = SomeArrayValueWithPath(castValue.ArrayValue(), castValue.Path(), nil, castValue.History()...)

		case *BoolValue:
			values[name] = SomeBoolValueWithPath(castValue.BoolValue(), castValue.Path(), nil, castValue.History()...)

		case *DecimalValue:
			values[name] = SomeDecimalValueWithPath(castValue.DecimalValue(), castValue.Path(), nil, castValue.History()...)

		case *StringValue:
			values[name] = SomeStringValueWithPath(castValue.StringValue(), castValue.Path(), nil, castValue.History()...)

		default:
			return nil, fmt.Errorf("can't copy value of type %T", value)
		}
	}

	return values, nil
}
