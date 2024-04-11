package macros

import (
	"github.com/mpvl/unique"
	"sort"
	"strconv"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/types"
)

type SeedTagsMacro struct {
}

func NewSeedTags() *SeedTagsMacro {
	return &SeedTagsMacro{}
}

func (*SeedTagsMacro) GetMacroDetails() MacroDetails {
	return MacroDetails{
		ID:          "seed-tags",
		Title:       "Seed Tags",
		Description: "This model macro simply seeds the model file with supported tags from all risk rules.",
	}
}

func (*SeedTagsMacro) GetNextQuestion(parsedModel *types.Model) (nextQuestion MacroQuestion, err error) {
	return NoMoreQuestions(), nil
}

func (*SeedTagsMacro) ApplyAnswer(_ string, _ ...string) (message string, validResult bool, err error) {
	return "Answer processed", true, nil
}

func (*SeedTagsMacro) GoBack() (message string, validResult bool, err error) {
	return "Cannot go back further", false, nil
}

func (*SeedTagsMacro) GetFinalChangeImpact(_ *input.Model, _ *types.Model) (changes []string, message string, validResult bool, err error) {
	return []string{"seed the model file with supported tags from all risk rules"}, "Changeset valid", true, err
}

func (*SeedTagsMacro) Execute(modelInput *input.Model, parsedModel *types.Model) (message string, validResult bool, err error) {
	modelInput.TagsAvailable = parsedModel.TagsAvailable
	for tag := range parsedModel.AllSupportedTags {
		modelInput.TagsAvailable = append(modelInput.TagsAvailable, tag)
	}
	unique.Strings(&modelInput.TagsAvailable)
	sort.Strings(modelInput.TagsAvailable)
	return "Model file seeding with " + strconv.Itoa(len(parsedModel.AllSupportedTags)) + " tags successful", true, nil
}
