package pretty_print

import (
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/macros"
)

func GetMacroDetails() macros.MacroDetails {
	return macros.MacroDetails{
		ID:          "pretty-print",
		Title:       "Pretty Print",
		Description: "This model macro simply reformats the model file in a pretty-print style.",
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
	return []string{"pretty-printing the model file"}, "Changeset valid", true, err
}

func Execute(_ *input.ModelInput) (message string, validResult bool, err error) {
	return "Model pretty printing successful", true, nil
}
