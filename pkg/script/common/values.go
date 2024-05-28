package common

import "fmt"

type Values map[string]Value

func (what Values) Copy() (Values, error) {
	values := make(Values, 0)
	for name, value := range what {
		switch castValue := value.(type) {
		case AnyValue:
			values[name] = SomeValue(castValue.Value(), castValue.History())

		case *AnyValue:
			values[name] = SomeValue(castValue.Value(), castValue.History())

		case ArrayValue:
			values[name] = SomeValue(castValue.ArrayValue(), castValue.History())

		case *ArrayValue:
			values[name] = SomeArrayValue(castValue.ArrayValue(), castValue.History())

		case BoolValue:
			values[name] = SomeBoolValue(castValue.BoolValue(), castValue.History())

		case *BoolValue:
			values[name] = SomeBoolValue(castValue.BoolValue(), castValue.History())

		case DecimalValue:
			values[name] = SomeDecimalValue(castValue.DecimalValue(), castValue.History())

		case *DecimalValue:
			values[name] = SomeDecimalValue(castValue.DecimalValue(), castValue.History())

		case StringValue:
			values[name] = SomeStringValue(castValue.StringValue(), castValue.History())

		case *StringValue:
			values[name] = SomeStringValue(castValue.StringValue(), castValue.History())

		default:
			return nil, fmt.Errorf("can't copy value of type %T", value)
		}
	}

	return values, nil
}
