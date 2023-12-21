package seed_risk_tracking

import (
	"github.com/threagile/threagile/model"
	"sort"
	"strconv"
)

func GetMacroDetails() model.MacroDetails {
	return model.MacroDetails{
		ID:          "seed-risk-tracking",
		Title:       "Seed Risk Tracking",
		Description: "This model macro simply seeds the model file with initial risk tracking entries for all untracked risks.",
	}
}

func GetNextQuestion() (nextQuestion model.MacroQuestion, err error) {
	return model.NoMoreQuestions(), nil
}

func ApplyAnswer(_ string, _ ...string) (message string, validResult bool, err error) {
	return "Answer processed", true, nil
}

func GoBack() (message string, validResult bool, err error) {
	return "Cannot go back further", false, nil
}

func GetFinalChangeImpact(_ *model.ModelInput) (changes []string, message string, validResult bool, err error) {
	return []string{"seed the model file with with initial risk tracking entries for all untracked risks"}, "Changeset valid", true, err
}

func Execute(modelInput *model.ModelInput) (message string, validResult bool, err error) {
	syntheticRiskIDsToCreateTrackingFor := make([]string, 0)
	for id, risk := range model.GeneratedRisksBySyntheticId {
		if !risk.IsRiskTracked() {
			syntheticRiskIDsToCreateTrackingFor = append(syntheticRiskIDsToCreateTrackingFor, id)
		}
	}
	sort.Strings(syntheticRiskIDsToCreateTrackingFor)
	if modelInput.RiskTracking == nil {
		modelInput.RiskTracking = make(map[string]model.InputRiskTracking)
	}
	for _, id := range syntheticRiskIDsToCreateTrackingFor {
		modelInput.RiskTracking[id] = model.InputRiskTracking{
			Status:        model.Unchecked.String(),
			Justification: "",
			Ticket:        "",
			Date:          "",
			CheckedBy:     "",
		}
	}
	return "Model file seeding with " + strconv.Itoa(len(syntheticRiskIDsToCreateTrackingFor)) + " initial risk tracking successful", true, nil
}
