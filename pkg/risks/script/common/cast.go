package common

import (
	"fmt"

	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/types"
)

const (
	authentication  = "authentication"
	authorization   = "authorization"
	confidentiality = "confidentiality"
	criticality     = "criticality"
	integrity       = "integrity"
	availability    = "availability"
	probability     = "probability"
	encryption      = "encryption"
	quantity        = "quantity"
	impact          = "impact"
	likelihood      = "likelihood"
	size            = "size"
)

var (
	cast = map[string]castFunc{
		authentication:  toAuthentication,
		authorization:   toAuthorization,
		confidentiality: toConfidentiality,
		criticality:     toCriticality,
		integrity:       toCriticality,
		availability:    toCriticality,
		probability:     toProbability,
		encryption:      toEncryption,
		quantity:        toQuantity,
		impact:          toImpact,
		likelihood:      toLikelihood,
		size:            toSize,
	}
)

type castFunc func(value Value) (Value, error)

func CastValue(value Value, castType string) (Value, error) {
	if value == nil {
		return NilValue(), nil
	}

	caster, ok := cast[castType]
	if !ok {
		return nil, fmt.Errorf("unknown cast type %v", castType)
	}

	return caster(value)
}

func toConfidentiality(value Value) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.Confidentiality(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), value.Event()), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), value.Event()), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), value.Event()), nil

	case Value:
		return toConfidentiality(castValue)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toCriticality(value Value) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.Criticality(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), value.Event()), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), value.Event()), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), value.Event()), nil

	case Value:
		return toCriticality(castValue)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toAuthentication(value Value) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.Authentication(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), value.Event()), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), value.Event()), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), value.Event()), nil

	case Value:
		return toAuthentication(castValue)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toAuthorization(value Value) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.Authorization(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), value.Event()), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), value.Event()), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), value.Event()), nil

	case Value:
		return toAuthorization(castValue)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toProbability(value Value) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.DataBreachProbability(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), value.Event()), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), value.Event()), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), value.Event()), nil

	case Value:
		return toProbability(castValue)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toEncryption(value Value) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.EncryptionStyle(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), value.Event()), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), value.Event()), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), value.Event()), nil

	case Value:
		return toEncryption(castValue)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toQuantity(value Value) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.Quantity(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), value.Event()), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), value.Event()), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), value.Event()), nil

	case Value:
		return toQuantity(castValue)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toImpact(value Value) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.RiskExploitationImpact(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), value.Event()), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), value.Event()), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), value.Event()), nil

	case Value:
		return toImpact(castValue)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toLikelihood(value Value) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.RiskExploitationLikelihood(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), value.Event()), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), value.Event()), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), value.Event()), nil

	case Value:
		return toLikelihood(castValue)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toSize(value Value) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.TechnicalAssetSize(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), value.Event()), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), value.Event()), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), value.Event()), nil

	case Value:
		return toSize(castValue)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}
