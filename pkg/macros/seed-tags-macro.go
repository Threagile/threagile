package macros

import (
	"sort"
	"strconv"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/types"
)

type seedTagsMacro struct {
}

func NewSeedTags() *seedTagsMacro {
	return &seedTagsMacro{}
}

func (*seedTagsMacro) GetMacroDetails() MacroDetails {
	return MacroDetails{
		ID:          "seed-tags",
		Title:       "Seed Tags",
		Description: "This model macro simply seeds the model file with supported tags from all risk rules.",
	}
}

func (*seedTagsMacro) GetNextQuestion(parsedModel *types.ParsedModel) (nextQuestion MacroQuestion, err error) {
	return NoMoreQuestions(), nil
}

func (*seedTagsMacro) ApplyAnswer(_ string, _ ...string) (message string, validResult bool, err error) {
	return "Answer processed", true, nil
}

func (*seedTagsMacro) GoBack() (message string, validResult bool, err error) {
	return "Cannot go back further", false, nil
}

func (*seedTagsMacro) GetFinalChangeImpact(_ *input.ModelInput, _ *types.ParsedModel) (changes []string, message string, validResult bool, err error) {
	return []string{"seed the model file with supported tags from all risk rules"}, "Changeset valid", true, err
}

func (*seedTagsMacro) Execute(modelInput *input.ModelInput, parsedModel *types.ParsedModel) (message string, validResult bool, err error) {
	tagMap := make(map[string]bool)
	for k, v := range parsedModel.AllSupportedTags {
		tagMap[k] = v
	}
	for _, tagFromModel := range parsedModel.TagsAvailable {
		tagMap[tagFromModel] = true
	}
	tagsSorted := make([]string, 0)
	for tag := range tagMap {
		tagsSorted = append(tagsSorted, tag)
	}
	sort.Strings(tagsSorted)
	modelInput.TagsAvailable = tagsSorted
	return "Model file seeding with " + strconv.Itoa(len(parsedModel.AllSupportedTags)) + " tags successful", true, nil
}
