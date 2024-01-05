package macros

import (
	"sort"
	"strconv"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/types"
)

type removeUnusedTagsMacro struct {
}

func NewRemoveUnusedTags() Macros {
	return &removeUnusedTagsMacro{}
}

func (*removeUnusedTagsMacro) GetMacroDetails() MacroDetails {
	return MacroDetails{
		ID:          "remove-unused-tags",
		Title:       "Remove Unused Tags",
		Description: "This model macro simply removes all unused tags from the model file.",
	}
}

func (*removeUnusedTagsMacro) GetNextQuestion(*types.ParsedModel) (nextQuestion MacroQuestion, err error) {
	return NoMoreQuestions(), nil
}

func (*removeUnusedTagsMacro) ApplyAnswer(_ string, _ ...string) (message string, validResult bool, err error) {
	return "Answer processed", true, nil
}

func (*removeUnusedTagsMacro) GoBack() (message string, validResult bool, err error) {
	return "Cannot go back further", false, nil
}

func (*removeUnusedTagsMacro) GetFinalChangeImpact(_ *input.ModelInput, _ *types.ParsedModel) (changes []string, message string, validResult bool, err error) {
	return []string{"remove unused tags from the model file"}, "Changeset valid", true, err
}

func (*removeUnusedTagsMacro) Execute(modelInput *input.ModelInput, parsedModel *types.ParsedModel) (message string, validResult bool, err error) {
	tagUsageMap := make(map[string]bool)
	for _, tag := range parsedModel.TagsAvailable {
		tagUsageMap[tag] = false // false = tag is not used
	}
	for _, dA := range parsedModel.DataAssets {
		for _, tag := range dA.Tags {
			tagUsageMap[tag] = true // true = tag is used
		}
	}
	for _, tA := range parsedModel.TechnicalAssets {
		for _, tag := range tA.Tags {
			tagUsageMap[tag] = true // true = tag is used
		}
		for _, cL := range tA.CommunicationLinks {
			for _, tag := range cL.Tags {
				tagUsageMap[tag] = true // true = tag is used
			}
		}
	}
	for _, tB := range parsedModel.TrustBoundaries {
		for _, tag := range tB.Tags {
			tagUsageMap[tag] = true // true = tag is used
		}
	}
	for _, sR := range parsedModel.SharedRuntimes {
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
	modelInput.TagsAvailable = tagsSorted
	return "Model file removal of " + strconv.Itoa(counter) + " unused tags successful", true, nil
}
