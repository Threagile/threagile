package risks

import (
	"github.com/threagile/threagile/model"
	"github.com/threagile/threagile/run"
	"log"
)

type BuiltInRisk struct {
	Category      func() model.RiskCategory
	SupportedTags func() []string
	GenerateRisks func(m *model.ModelInput) []model.Risk
}

type CustomRisk struct {
	ID       string
	Category model.RiskCategory
	Tags     []string
	Runner   *run.Runner
}

func (r *CustomRisk) GenerateRisks(m *model.ParsedModel) []model.Risk {
	if r.Runner == nil {
		return nil
	}

	risks := make([]model.Risk, 0)
	runError := r.Runner.Run(m, &risks, "-generate-risks")
	if runError != nil {
		log.Fatalf("Failed to generate risks for custom risk rule %q: %v\n", r.Runner.Filename, runError)
	}

	return risks
}
