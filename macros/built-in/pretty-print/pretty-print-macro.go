package pretty_print

import "github.com/threagile/threagile/model"

func GetMacroDetails() model.MacroDetails {
	return model.MacroDetails{
		ID:          "pretty-print",
		Title:       "Pretty Print",
		Description: "This model macro simply reformats the model file in a pretty-print style.",
	}
}

func GetNextQuestion() (nextQuestion model.MacroQuestion, err error) {
	return model.NoMoreQuestions(), nil
}

func ApplyAnswer(questionID string, answer ...string) (message string, validResult bool, err error) {
	return "Answer processed", true, nil
}

func GoBack() (message string, validResult bool, err error) {
	return "Cannot go back further", false, nil
}

func GetFinalChangeImpact(modelInput *model.ModelInput) (changes []string, message string, validResult bool, err error) {
	return []string{"pretty-printing the model file"}, "Changeset valid", true, err
}

func Execute(modelInput *model.ModelInput) (message string, validResult bool, err error) {
	return "Model pretty printing successful", true, nil
}
