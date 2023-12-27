package seed_tags

import (
	"github.com/threagile/threagile/pkg/security/types"
	"sort"
	"strconv"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/macros"
)

func GetMacroDetails() macros.MacroDetails {
	return macros.MacroDetails{
		ID:          "seed-tags",
		Title:       "Seed Tags",
		Description: "This model macro simply seeds the model file with supported tags from all risk rules.",
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
	return []string{"seed the model file with supported tags from all risk rules"}, "Changeset valid", true, err
}

func Execute(modelInput *input.ModelInput, parsedModel *types.ParsedModel) (message string, validResult bool, err error) {
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
