package types

import (
	"github.com/threagile/threagile/pkg/run"
	"log"
)

type CustomRisk struct {
	ID       string
	Category RiskCategory
	Tags     []string
	Runner   *run.Runner
}

func (r *CustomRisk) GenerateRisks(m *ParsedModel) []Risk {
	if r.Runner == nil {
		return nil
	}

	risks := make([]Risk, 0)
	runError := r.Runner.Run(m, &risks, "-generate-risks")
	if runError != nil {
		log.Fatalf("Failed to generate risks for custom risk rule %q: %v\n", r.Runner.Filename, runError)
	}

	return risks
}
