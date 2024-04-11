package macros

import (
	"sort"
	"strconv"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/types"
)

type SeedRiskTrackingMacro struct {
}

func NewSeedRiskTracking() *SeedRiskTrackingMacro {
	return &SeedRiskTrackingMacro{}
}

func (*SeedRiskTrackingMacro) GetMacroDetails() MacroDetails {
	return MacroDetails{
		ID:          "seed-risk-tracking",
		Title:       "Seed Risk Tracking",
		Description: "This model macro simply seeds the model file with initial risk tracking entries for all untracked risks.",
	}
}

func (*SeedRiskTrackingMacro) GetNextQuestion(*types.Model) (nextQuestion MacroQuestion, err error) {
	return NoMoreQuestions(), nil
}

func (*SeedRiskTrackingMacro) ApplyAnswer(_ string, _ ...string) (message string, validResult bool, err error) {
	return "Answer processed", true, nil
}

func (*SeedRiskTrackingMacro) GoBack() (message string, validResult bool, err error) {
	return "Cannot go back further", false, nil
}

func (*SeedRiskTrackingMacro) GetFinalChangeImpact(_ *input.Model, _ *types.Model) (changes []string, message string, validResult bool, err error) {
	return []string{"seed the model file with with initial risk tracking entries for all untracked risks"}, "Changeset valid", true, err
}

func (*SeedRiskTrackingMacro) Execute(modelInput *input.Model, parsedModel *types.Model) (message string, validResult bool, err error) {
	syntheticRiskIDsToCreateTrackingFor := make([]string, 0)
	for id, risk := range parsedModel.GeneratedRisksBySyntheticId {
		if !risk.IsRiskTracked(parsedModel) {
			syntheticRiskIDsToCreateTrackingFor = append(syntheticRiskIDsToCreateTrackingFor, id)
		}
	}
	sort.Strings(syntheticRiskIDsToCreateTrackingFor)
	if modelInput.RiskTracking == nil {
		modelInput.RiskTracking = make(map[string]input.RiskTracking)
	}
	for _, id := range syntheticRiskIDsToCreateTrackingFor {
		modelInput.RiskTracking[id] = input.RiskTracking{
			Status:        types.Unchecked.String(),
			Justification: "",
			Ticket:        "",
			Date:          "",
			CheckedBy:     "",
		}
	}
	return "Model file seeding with " + strconv.Itoa(len(syntheticRiskIDsToCreateTrackingFor)) + " initial risk tracking successful", true, nil
}
