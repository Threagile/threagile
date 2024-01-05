package macros

import (
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/types"
)

type prettyPrintMacro struct {
}

func NewPrettyPrint() Macros {
	return &prettyPrintMacro{}
}

func (*prettyPrintMacro) GetMacroDetails() MacroDetails {
	return MacroDetails{
		ID:          "pretty-print",
		Title:       "Pretty Print",
		Description: "This model macro simply reformats the model file in a pretty-print style.",
	}
}

func (*prettyPrintMacro) GetNextQuestion(_ *types.ParsedModel) (nextQuestion MacroQuestion, err error) {
	return NoMoreQuestions(), nil
}

func (*prettyPrintMacro) ApplyAnswer(_ string, _ ...string) (message string, validResult bool, err error) {
	return "Answer processed", true, nil
}

func (*prettyPrintMacro) GoBack() (message string, validResult bool, err error) {
	return "Cannot go back further", false, nil
}

func (*prettyPrintMacro) GetFinalChangeImpact(_ *input.ModelInput, _ *types.ParsedModel) (changes []string, message string, validResult bool, err error) {
	return []string{"pretty-printing the model file"}, "Changeset valid", true, err
}

func (*prettyPrintMacro) Execute(_ *input.ModelInput, _ *types.ParsedModel) (message string, validResult bool, err error) {
	return "Model pretty printing successful", true, nil
}
