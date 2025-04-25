package model

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/threagile/threagile/pkg/types"
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

func (what *CustomRiskCategory) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	if what.runner == nil {
		return nil, nil
	}

	generatedRisks := make([]*types.Risk, 0)
	runError := what.runner.Run(parsedModel, &generatedRisks, "-generate-risks")
	if runError != nil {
		return nil, fmt.Errorf("failed to generate risks for custom risk rule %q: %w", what.runner.Filename, runError)
	}

	return generatedRisks, nil
}

func LoadCustomRiskRules(pluginDir string, pluginFiles []string, reporter types.ProgressReporter) types.RiskRules {
	customRiskRuleList := make([]string, 0)
	customRiskRules := make(types.RiskRules)
	if len(pluginFiles) > 0 {
		reporter.Info("Loading custom risk rules:", strings.Join(pluginFiles, ", "))

		for _, pluginFile := range pluginFiles {
			if len(pluginFile) > 0 {
				newRunner, loadError := new(runner).Load(filepath.Join(pluginDir, pluginFile))
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
