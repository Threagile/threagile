package common

import (
	"fmt"

	"github.com/threagile/threagile/pkg/types"
)

const (
	calculateSeverity = "calculate_severity"
)

var (
	callers = map[string]builtInFunc{
		calculateSeverity: calculateSeverityFunc,
	}
)

type builtInFunc func(parameters []Value) (any, error)

func IsBuiltIn(builtInName string) bool {
	_, ok := callers[builtInName]
	return ok
}

func CallBuiltIn(builtInName string, parameters ...Value) (any, error) {
	caller, ok := callers[builtInName]
	if !ok {
		return nil, fmt.Errorf("unknown built-in %v", builtInName)
	}

	return caller(parameters)
}

func calculateSeverityFunc(parameters []Value) (any, error) {
	if len(parameters) != 2 {
		return nil, fmt.Errorf("failed to calculate severity: expected 2 parameters, got %d", len(parameters))
	}

	likelihoodValue, likelihoodError := toLikelihood(parameters[0])
	if likelihoodError != nil {
		return nil, fmt.Errorf("failed to calculate severity: %v", likelihoodError)
	}

	impactValue, impactError := toImpact(parameters[1])
	if impactError != nil {
		return nil, fmt.Errorf("failed to calculate severity: %v", impactError)
	}

	return types.CalculateSeverity(likelihoodValue.(types.RiskExploitationLikelihood), impactValue.(types.RiskExploitationImpact)).String(), nil
}
