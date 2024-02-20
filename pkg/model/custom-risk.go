package model

import (
	"fmt"
	"log"
	"strings"

	"github.com/threagile/threagile/pkg/security/types"
)

type CustomRisk struct {
	id       string
	category types.RiskCategory
	tags     []string
	runner   *runner
}

func (what *CustomRisk) Init(id string, category types.RiskCategory, tags []string) *CustomRisk {
	*what = CustomRisk{
		id:       id,
		category: category,
		tags:     tags,
	}

	return what
}

func (what *CustomRisk) Category() types.RiskCategory {
	return what.category
}

func (what *CustomRisk) SupportedTags() []string {
	return what.tags
}

func (what *CustomRisk) GenerateRisks(parsedModel *types.ParsedModel) []types.Risk {
	if what.runner == nil {
		return nil
	}

	risks := make([]types.Risk, 0)
	runError := what.runner.Run(parsedModel, &risks, "-generate-risks")
	if runError != nil {
		log.Fatalf("Failed to generate risks for custom risk rule %q: %v\n", what.runner.Filename, runError)
	}

	return risks
}

func (what *CustomRisk) MatchRisk(parsedModel *types.ParsedModel, risk string) bool {
	categoryId := what.category.Id
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		techAsset := parsedModel.TechnicalAssets[id]
		if strings.EqualFold(risk, categoryId+"@"+techAsset.Id) {
			return true
		}
	}

	return false
}

func (what *CustomRisk) ExplainRisk(parsedModel *types.ParsedModel, risk string) []string {
	if what.runner == nil {
		return nil
	}

	explanation := make([]string, 0)
	runError := what.runner.Run(parsedModel, &explanation, "-explain-risk", risk)
	if runError != nil {
		log.Fatalf("Failed to explain risk %q for custom risk rule %q: %v\n", risk, what.runner.Filename, runError)
	}

	return explanation
}

func LoadCustomRiskRules(pluginFiles []string, reporter types.ProgressReporter) map[string]*CustomRisk {
	customRiskRuleList := make([]string, 0)
	customRiskRules := make(map[string]*CustomRisk)
	if len(pluginFiles) > 0 {
		reporter.Info("Loading custom risk rules:", strings.Join(pluginFiles, ", "))

		for _, pluginFile := range pluginFiles {
			if len(pluginFile) > 0 {
				runner, loadError := new(runner).Load(pluginFile)
				if loadError != nil {
					reporter.Error(fmt.Sprintf("WARNING: Custom risk rule %q not loaded: %v\n", pluginFile, loadError))
				}

				risk := new(CustomRisk)
				runError := runner.Run(nil, &risk, "-get-info")
				if runError != nil {
					reporter.Error(fmt.Sprintf("WARNING: Failed to get info for custom risk rule %q: %v\n", pluginFile, runError))
				}

				risk.runner = runner
				customRiskRules[risk.id] = risk
				customRiskRuleList = append(customRiskRuleList, risk.id)
				reporter.Info("Custom risk rule loaded:", risk.id)
			}
		}

		reporter.Info("Loaded custom risk rules:", strings.Join(customRiskRuleList, ", "))
	}

	return customRiskRules
}
