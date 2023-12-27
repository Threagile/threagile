package seed_risk_tracking

import (
	"sort"
	"strconv"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/security/types"
)

func GetMacroDetails() macros.MacroDetails {
	return macros.MacroDetails{
		ID:          "seed-risk-tracking",
		Title:       "Seed Risk Tracking",
		Description: "This model macro simply seeds the model file with initial risk tracking entries for all untracked risks.",
	}
}

func GetNextQuestion() (nextQuestion macros.MacroQuestion, err error) {
	return macros.NoMoreQuestions(), nil
}

func ApplyAnswer(_ string, _ ...string) (message string, validResult bool, err error) {
	return "Answer processed", true, nil
}

func GoBack() (message string, validResult bool, err error) {
	return "Cannot go back further", false, nil
}

func GetFinalChangeImpact(_ *input.ModelInput) (changes []string, message string, validResult bool, err error) {
	return []string{"seed the model file with with initial risk tracking entries for all untracked risks"}, "Changeset valid", true, err
}

func Execute(parsedModel *types.ParsedModel, modelInput *input.ModelInput) (message string, validResult bool, err error) {
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
