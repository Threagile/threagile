package seed_tags

import (
	"github.com/threagile/threagile/model"
	"sort"
	"strconv"
)

func GetMacroDetails() model.MacroDetails {
	return model.MacroDetails{
		ID:          "seed-tags",
		Title:       "Seed Tags",
		Description: "This model macro simply seeds the model file with supported tags from all risk rules.",
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
	return []string{"seed the model file with supported tags from all risk rules"}, "Changeset valid", true, err
}

func Execute(modelInput *model.ModelInput) (message string, validResult bool, err error) {
	tagMap := make(map[string]bool, 0)
	for k, v := range model.AllSupportedTags {
		tagMap[k] = v
	}
	for _, tagFromModel := range model.ParsedModelRoot.TagsAvailable {
		tagMap[tagFromModel] = true
	}
	tagsSorted := make([]string, 0)
	for tag := range tagMap {
		tagsSorted = append(tagsSorted, tag)
	}
	sort.Strings(tagsSorted)
	modelInput.Tags_available = tagsSorted
	return "Model file seeding with " + strconv.Itoa(len(model.AllSupportedTags)) + " tags successful", true, nil
}
