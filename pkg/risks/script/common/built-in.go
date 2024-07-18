package common

import (
	"fmt"

	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/risks/script/event"
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

type builtInFunc func(parameters []Value, stack Stack, events ...event.Event) (Value, error)

func IsBuiltIn(builtInName string) bool {
	_, ok := callers[builtInName]
	return ok
}

func CallBuiltIn(builtInName string, stack Stack, events []event.Event, parameters ...Value) (Value, error) {
	caller, ok := callers[builtInName]
	if !ok {
		return nil, fmt.Errorf("unknown built-in %v", builtInName)
	}

	return caller(parameters, stack, events...)
}

func calculateSeverityFunc(parameters []Value, stack Stack, events ...event.Event) (Value, error) {
	if len(parameters) != 2 {
		return nil, fmt.Errorf("failed to calculate severity: expected 2 parameters, got %d", len(parameters))
	}

	likelihoodValue, likelihoodError := toLikelihood(parameters[0], stack, events...)
	if likelihoodError != nil {
		return nil, fmt.Errorf("failed to calculate severity: %w", likelihoodError)
	}
	likelihoodDecimal := likelihoodValue.Value().(decimal.Decimal).IntPart()

	impactValue, impactError := toImpact(parameters[1], stack, events...)
	if impactError != nil {
		return nil, fmt.Errorf("failed to calculate severity: %w", impactError)
	}
	impactDecimal := impactValue.Value().(decimal.Decimal).IntPart()

	return SomeStringValue(types.CalculateSeverity(types.RiskExploitationLikelihood(likelihoodDecimal), types.RiskExploitationImpact(impactDecimal)).String(), stack), nil
}
