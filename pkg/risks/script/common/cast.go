package common

import (
	"fmt"

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

type castFunc func(value any) (any, error)

func CastValue(value any, castType string) (any, error) {
	caster, ok := cast[castType]
	if !ok {
		return nil, fmt.Errorf("unknown cast type %v", castType)
	}

	return caster(value)
}

func toConfidentiality(value any) (any, error) {
	switch castValue := value.(type) {
	case string:
		return types.Confidentiality(0).Find(castValue)

	case fmt.Stringer:
		return types.Confidentiality(0).Find(castValue.String())

	case int, int64:
		return castValue, nil

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}

func toCriticality(value any) (any, error) {
	switch castValue := value.(type) {
	case string:
		return types.Criticality(0).Find(castValue)

	case fmt.Stringer:
		return types.Criticality(0).Find(castValue.String())

	case int, int64:
		return castValue, nil

	default:
		return nil, fmt.Errorf("toCriticality: unexpected type %T", value)
	}
}

func toAuthentication(value any) (any, error) {
	switch castValue := value.(type) {
	case string:
		return types.Authentication(0).Find(castValue)

	case fmt.Stringer:
		return types.Authentication(0).Find(castValue.String())

	case int, int64:
		return castValue, nil

	default:
		return nil, fmt.Errorf("toAuthentication: unexpected type %T", value)
	}
}

func toAuthorization(value any) (any, error) {
	switch castValue := value.(type) {
	case string:
		return types.Authorization(0).Find(castValue)

	case fmt.Stringer:
		return types.Authorization(0).Find(castValue.String())

	case int, int64:
		return castValue, nil

	default:
		return nil, fmt.Errorf("toAuthorization: unexpected type %T", value)
	}
}

func toProbability(value any) (any, error) {
	switch castValue := value.(type) {
	case string:
		return types.DataBreachProbability(0).Find(castValue)

	case fmt.Stringer:
		return types.DataBreachProbability(0).Find(castValue.String())

	case int, int64:
		return castValue, nil

	default:
		return nil, fmt.Errorf("toProbability: unexpected type %T", value)
	}
}

func toEncryption(value any) (any, error) {
	switch castValue := value.(type) {
	case string:
		return types.EncryptionStyle(0).Find(castValue)

	case fmt.Stringer:
		return types.EncryptionStyle(0).Find(castValue.String())

	case int, int64:
		return castValue, nil

	default:
		return nil, fmt.Errorf("toEncryption: unexpected type %T", value)
	}
}

func toQuantity(value any) (any, error) {
	switch castValue := value.(type) {
	case string:
		return types.Quantity(0).Find(castValue)

	case fmt.Stringer:
		return types.Quantity(0).Find(castValue.String())

	case int, int64:
		return castValue, nil

	default:
		return nil, fmt.Errorf("toQuantity: unexpected type %T", value)
	}
}

func toImpact(value any) (any, error) {
	switch castValue := value.(type) {
	case string:
		return types.RiskExploitationImpact(0).Find(castValue)

	case fmt.Stringer:
		return types.RiskExploitationImpact(0).Find(castValue.String())

	case int, int64:
		return castValue, nil

	default:
		return nil, fmt.Errorf("toImpact: unexpected type %T", value)
	}
}

func toLikelihood(value any) (any, error) {
	switch castValue := value.(type) {
	case string:
		return types.RiskExploitationLikelihood(0).Find(castValue)

	case fmt.Stringer:
		return types.RiskExploitationLikelihood(0).Find(castValue.String())

	case int, int64:
		return castValue, nil

	default:
		return nil, fmt.Errorf("toLikelihood: unexpected type %T", value)
	}
}

func toSize(value any) (any, error) {
	switch castValue := value.(type) {
	case string:
		return types.TechnicalAssetSize(0).Find(castValue)

	case fmt.Stringer:
		return types.TechnicalAssetSize(0).Find(castValue.String())

	case int, int64:
		return castValue, nil

	default:
		return nil, fmt.Errorf("toSize: unexpected type %T", value)
	}
}
