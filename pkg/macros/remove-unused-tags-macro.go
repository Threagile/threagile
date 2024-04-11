package macros

import (
	"github.com/mpvl/unique"
	"sort"
	"strconv"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/types"
)

type removeUnusedTagsMacro struct {
}

func newRemoveUnusedTags() *removeUnusedTagsMacro {
	return &removeUnusedTagsMacro{}
}

func (*removeUnusedTagsMacro) GetMacroDetails() MacroDetails {
	return MacroDetails{
		ID:          "remove-unused-tags",
		Title:       "Remove Unused Tags",
		Description: "This model macro simply removes all unused tags from the model file.",
	}
}

func (*removeUnusedTagsMacro) GetNextQuestion(*types.Model) (nextQuestion MacroQuestion, err error) {
	return NoMoreQuestions(), nil
}

func (*removeUnusedTagsMacro) ApplyAnswer(_ string, _ ...string) (message string, validResult bool, err error) {
	return "Answer processed", true, nil
}

func (*removeUnusedTagsMacro) GoBack() (message string, validResult bool, err error) {
	return "Cannot go back further", false, nil
}

func (*removeUnusedTagsMacro) GetFinalChangeImpact(_ *input.Model, _ *types.Model) (changes []string, message string, validResult bool, err error) {
	return []string{"remove unused tags from the model file"}, "Changeset valid", true, err
}

func (*removeUnusedTagsMacro) Execute(modelInput *input.Model, parsedModel *types.Model) (message string, validResult bool, err error) {
	modelInput.TagsAvailable = parsedModel.TagsAvailable
	for _, asset := range parsedModel.DataAssets {
		modelInput.TagsAvailable = append(modelInput.TagsAvailable, asset.Tags...)
	}
	for _, asset := range parsedModel.TechnicalAssets {
		modelInput.TagsAvailable = append(modelInput.TagsAvailable, asset.Tags...)
		for _, link := range asset.CommunicationLinks {
			modelInput.TagsAvailable = append(modelInput.TagsAvailable, link.Tags...)
		}
	}
	for _, boundary := range parsedModel.TrustBoundaries {
		modelInput.TagsAvailable = append(modelInput.TagsAvailable, boundary.Tags...)
	}
	for _, runtime := range parsedModel.SharedRuntimes {
		modelInput.TagsAvailable = append(modelInput.TagsAvailable, runtime.Tags...)
	}
	count := len(modelInput.TagsAvailable)
	unique.Strings(&modelInput.TagsAvailable)
	sort.Strings(modelInput.TagsAvailable)
	return "Model file removal of " + strconv.Itoa(count-len(modelInput.TagsAvailable)) + " unused tags successful", true, nil
}
