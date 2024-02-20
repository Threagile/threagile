package macros

import (
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/types"
)

type PrettyPrintMacro struct {
}

func NewPrettyPrint() *PrettyPrintMacro {
	return &PrettyPrintMacro{}
}

func (*PrettyPrintMacro) GetMacroDetails() MacroDetails {
	return MacroDetails{
		ID:          "pretty-print",
		Title:       "Pretty Print",
		Description: "This model macro simply reformats the model file in a pretty-print style.",
	}
}

func (*PrettyPrintMacro) GetNextQuestion(_ *types.ParsedModel) (nextQuestion MacroQuestion, err error) {
	return NoMoreQuestions(), nil
}

func (*PrettyPrintMacro) ApplyAnswer(_ string, _ ...string) (message string, validResult bool, err error) {
	return "Answer processed", true, nil
}

func (*PrettyPrintMacro) GoBack() (message string, validResult bool, err error) {
	return "Cannot go back further", false, nil
}

func (*PrettyPrintMacro) GetFinalChangeImpact(_ *input.Model, _ *types.ParsedModel) (changes []string, message string, validResult bool, err error) {
	return []string{"pretty-printing the model file"}, "Changeset valid", true, err
}

func (*PrettyPrintMacro) Execute(_ *input.Model, _ *types.ParsedModel) (message string, validResult bool, err error) {
	return "Model pretty printing successful", true, nil
}
