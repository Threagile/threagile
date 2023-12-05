package remove_unused_tags

import (
	"github.com/threagile/threagile/model"
	"sort"
	"strconv"
)

func GetMacroDetails() model.MacroDetails {
	return model.MacroDetails{
		ID:          "remove-unused-tags",
		Title:       "Remove Unused Tags",
		Description: "This model macro simply removes all unused tags from the model file.",
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
	return []string{"remove unused tags from the model file"}, "Changeset valid", true, err
}

func Execute(modelInput *model.ModelInput) (message string, validResult bool, err error) {
	tagUsageMap := make(map[string]bool, 0)
	for _, tag := range model.ParsedModelRoot.TagsAvailable {
		tagUsageMap[tag] = false // false = tag is not used
	}
	for _, dA := range model.ParsedModelRoot.DataAssets {
		for _, tag := range dA.Tags {
			tagUsageMap[tag] = true // true = tag is used
		}
	}
	for _, tA := range model.ParsedModelRoot.TechnicalAssets {
		for _, tag := range tA.Tags {
			tagUsageMap[tag] = true // true = tag is used
		}
		for _, cL := range tA.CommunicationLinks {
			for _, tag := range cL.Tags {
				tagUsageMap[tag] = true // true = tag is used
			}
		}
	}
	for _, tB := range model.ParsedModelRoot.TrustBoundaries {
		for _, tag := range tB.Tags {
			tagUsageMap[tag] = true // true = tag is used
		}
	}
	for _, sR := range model.ParsedModelRoot.SharedRuntimes {
		for _, tag := range sR.Tags {
			tagUsageMap[tag] = true // true = tag is used
		}
	}
	counter := 0
	tagsSorted := make([]string, 0)
	for tag, used := range tagUsageMap {
		if used {
			tagsSorted = append(tagsSorted, tag)
		} else {
			counter++
		}
	}
	sort.Strings(tagsSorted)
	modelInput.Tags_available = tagsSorted
	return "Model file removal of " + strconv.Itoa(counter) + " unused tags successful", true, nil
}
