package macros

import (
	"sort"
	"strconv"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/types"
)

type seedRiskTrackingMacro struct {
}

func NewSeedRiskTracking() *seedRiskTrackingMacro {
	return &seedRiskTrackingMacro{}
}

func (*seedRiskTrackingMacro) GetMacroDetails() MacroDetails {
	return MacroDetails{
		ID:          "seed-risk-tracking",
		Title:       "Seed Risk Tracking",
		Description: "This model macro simply seeds the model file with initial risk tracking entries for all untracked risks.",
	}
}

func (*seedRiskTrackingMacro) GetNextQuestion(*types.ParsedModel) (nextQuestion MacroQuestion, err error) {
	return NoMoreQuestions(), nil
}

func (*seedRiskTrackingMacro) ApplyAnswer(_ string, _ ...string) (message string, validResult bool, err error) {
	return "Answer processed", true, nil
}

func (*seedRiskTrackingMacro) GoBack() (message string, validResult bool, err error) {
	return "Cannot go back further", false, nil
}

func (*seedRiskTrackingMacro) GetFinalChangeImpact(_ *input.ModelInput, _ *types.ParsedModel) (changes []string, message string, validResult bool, err error) {
	return []string{"seed the model file with with initial risk tracking entries for all untracked risks"}, "Changeset valid", true, err
}

func (*seedRiskTrackingMacro) Execute(modelInput *input.ModelInput, parsedModel *types.ParsedModel) (message string, validResult bool, err error) {
	syntheticRiskIDsToCreateTrackingFor := make([]string, 0)
	for id, risk := range parsedModel.GeneratedRisksBySyntheticId {
		if !risk.IsRiskTracked(parsedModel) {
			syntheticRiskIDsToCreateTrackingFor = append(syntheticRiskIDsToCreateTrackingFor, id)
		}
	}
	sort.Strings(syntheticRiskIDsToCreateTrackingFor)
	if modelInput.RiskTracking == nil {
		modelInput.RiskTracking = make(map[string]input.InputRiskTracking)
	}
	for _, id := range syntheticRiskIDsToCreateTrackingFor {
		modelInput.RiskTracking[id] = input.InputRiskTracking{
			Status:        types.Unchecked.String(),
			Justification: "",
			Ticket:        "",
			Date:          "",
			CheckedBy:     "",
		}
	}
	return "Model file seeding with " + strconv.Itoa(len(syntheticRiskIDsToCreateTrackingFor)) + " initial risk tracking successful", true, nil
}
