package common

import "fmt"

type Values map[string]Value

func (what Values) Copy() (Values, error) {
	values := make(Values, 0)
	for name, value := range what {
		switch castValue := value.(type) {
		case *AnyValue:
			values[name] = SomeValue(castValue.Value(), castValue.Event())

		case *ArrayValue:
			values[name] = SomeArrayValue(castValue.ArrayValue(), castValue.Event())

		case *BoolValue:
			values[name] = SomeBoolValue(castValue.BoolValue(), castValue.Event())

		case *DecimalValue:
			values[name] = SomeDecimalValue(castValue.DecimalValue(), castValue.Event())

		case *StringValue:
			values[name] = SomeStringValue(castValue.StringValue(), castValue.Event())

		default:
			return nil, fmt.Errorf("can't copy value of type %T", value)
		}
	}

	return values, nil
}
