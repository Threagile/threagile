package model

import (
	"fmt"
	"github.com/threagile/threagile/pkg/security/risks"
	"log"
	"strings"

	"github.com/threagile/threagile/pkg/security/types"
)

type CustomRiskCategory struct {
	types.RiskCategory `json:"risk_category" yaml:"risk_category,omitempty"`

	Tags   []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	runner *runner
}

func (what *CustomRiskCategory) Init(category *types.RiskCategory, tags []string) *CustomRiskCategory {
	*what = CustomRiskCategory{
		RiskCategory: *category,
		Tags:         tags,
	}

	return what
}

func (what *CustomRiskCategory) Category() *types.RiskCategory {
	return &what.RiskCategory
}

func (what *CustomRiskCategory) SupportedTags() []string {
	return what.Tags
}

func (what *CustomRiskCategory) GenerateRisks(parsedModel *types.Model) []*types.Risk {
	if what.runner == nil {
		return nil
	}

	generatedRisks := make([]*types.Risk, 0)
	runError := what.runner.Run(parsedModel, &generatedRisks, "-generate-risks")
	if runError != nil {
		log.Fatalf("Failed to generate risks for custom risk rule %q: %v\n", what.runner.Filename, runError)
	}

	return generatedRisks
}

func LoadCustomRiskRules(pluginFiles []string, reporter types.ProgressReporter) risks.RiskRules {
	customRiskRuleList := make([]string, 0)
	customRiskRules := make(risks.RiskRules)
	if len(pluginFiles) > 0 {
		reporter.Info("Loading custom risk rules:", strings.Join(pluginFiles, ", "))

		for _, pluginFile := range pluginFiles {
			if len(pluginFile) > 0 {
				newRunner, loadError := new(runner).Load(pluginFile)
				if loadError != nil {
					reporter.Error(fmt.Sprintf("WARNING: Custom risk rule %q not loaded: %v\n", pluginFile, loadError))
				}

				risk := new(CustomRiskCategory)
				runError := newRunner.Run(nil, &risk, "-get-info")
				if runError != nil {
					reporter.Error(fmt.Sprintf("WARNING: Failed to get info for custom risk rule %q: %v\n", pluginFile, runError))
				}

				risk.runner = newRunner
				customRiskRules[risk.ID] = risk
				customRiskRuleList = append(customRiskRuleList, risk.ID)
				reporter.Info("Custom risk rule loaded:", risk.ID)
			}
		}

		reporter.Info("Loaded custom risk rules:", strings.Join(customRiskRuleList, ", "))
	}

	return customRiskRules
}
