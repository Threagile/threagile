package common

import (
	"fmt"

	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/risks/script/event"
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

type castFunc func(value Value, stack Stack, events ...event.Event) (Value, error)

func CastValue(value Value, stack Stack, castType string) (Value, error) {
	if value == nil {
		return NilValue(), nil
	}

	caster, ok := cast[castType]
	if !ok {
		return nil, fmt.Errorf("unknown cast type %v", castType)
	}

	return caster(value, stack, value.History()...)
}

func toConfidentiality(value Value, stack Stack, events ...event.Event) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.Confidentiality(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), stack, events...), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), stack, events...), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), stack, events...), nil

	case Value:
		return toConfidentiality(castValue, stack, events...)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toCriticality(value Value, stack Stack, events ...event.Event) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.Criticality(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), stack, events...), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), stack, events...), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), stack, events...), nil

	case Value:
		return toCriticality(castValue, stack, events...)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toAuthentication(value Value, stack Stack, events ...event.Event) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.Authentication(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), stack, events...), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), stack, events...), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), stack, events...), nil

	case Value:
		return toAuthentication(castValue, stack, events...)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toAuthorization(value Value, stack Stack, events ...event.Event) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.Authorization(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), stack, events...), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), stack, events...), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), stack, events...), nil

	case Value:
		return toAuthorization(castValue, stack, events...)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toProbability(value Value, stack Stack, events ...event.Event) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.DataBreachProbability(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), stack, events...), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), stack, events...), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), stack, events...), nil

	case Value:
		return toProbability(castValue, stack, events...)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toEncryption(value Value, stack Stack, events ...event.Event) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.EncryptionStyle(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), stack, events...), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), stack, events...), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), stack, events...), nil

	case Value:
		return toEncryption(castValue, stack, events...)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toQuantity(value Value, stack Stack, events ...event.Event) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.Quantity(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), stack, events...), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), stack, events...), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), stack, events...), nil

	case Value:
		return toQuantity(castValue, stack, events...)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toImpact(value Value, stack Stack, events ...event.Event) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.RiskExploitationImpact(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), stack, events...), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), stack, events...), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), stack, events...), nil

	case Value:
		return toImpact(castValue, stack, events...)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toLikelihood(value Value, stack Stack, events ...event.Event) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.RiskExploitationLikelihood(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), stack, events...), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), stack, events...), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), stack, events...), nil

	case Value:
		return toLikelihood(castValue, stack, events...)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toSize(value Value, stack Stack, events ...event.Event) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := types.TechnicalAssetSize(0).Find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), stack, events...), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), stack, events...), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), stack, events...), nil

	case Value:
		return toSize(castValue, stack, events...)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}
