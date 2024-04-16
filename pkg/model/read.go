package model

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/risks"
	"github.com/threagile/threagile/pkg/security/types"
)

type ReadResult struct {
	ModelInput       *input.Model
	ParsedModel      *types.Model
	IntroTextRAA     string
	BuiltinRiskRules types.RiskRules
	CustomRiskRules  types.RiskRules
}

func (what ReadResult) ExplainRisk(cfg *common.Config, risk string, reporter common.DefaultProgressReporter) error {
	return fmt.Errorf("not implemented")
}

// TODO: consider about splitting this function into smaller ones for better reusability

func ReadAndAnalyzeModel(config *common.Config, progressReporter types.ProgressReporter) (*ReadResult, error) {
	progressReporter.Infof("Writing into output directory: %v", config.OutputFolder)
	progressReporter.Infof("Parsing model: %v", config.InputFile)

	builtinRiskRules := risks.GetBuiltInRiskRules()
	customRiskRules := LoadCustomRiskRules(config.RiskRulesPlugins, progressReporter)

	modelInput := new(input.Model).Defaults()
	loadError := modelInput.Load(config.InputFile)
	if loadError != nil {
		return nil, fmt.Errorf("unable to load model yaml: %v", loadError)
	}

	parsedModel, parseError := ParseModel(config, modelInput, builtinRiskRules, customRiskRules)
	if parseError != nil {
		return nil, fmt.Errorf("unable to parse model yaml: %v", parseError)
	}

	/**
	jsonData, _ := json.MarshalIndent(parsedModel, "", "  ")
	_ = os.WriteFile("parsed-model.json", jsonData, 0600)

	yamlData, _ := yaml.Marshal(parsedModel)
	_ = os.WriteFile("parsed-model.yaml", yamlData, 0600)
	/**/

	introTextRAA := applyRAA(parsedModel, config.PluginFolder, config.RAAPlugin, progressReporter)

	applyRiskGeneration(parsedModel, builtinRiskRules.Merge(customRiskRules), config.SkipRiskRules, progressReporter)
	err := parsedModel.ApplyWildcardRiskTrackingEvaluation(config.IgnoreOrphanedRiskTracking, progressReporter)
	if err != nil {
		return nil, fmt.Errorf("unable to apply wildcard risk tracking evaluation: %v", err)
	}

	err = parsedModel.CheckRiskTracking(config.IgnoreOrphanedRiskTracking, progressReporter)
	if err != nil {
		return nil, fmt.Errorf("unable to check risk tracking: %v", err)
	}

	return &ReadResult{
		ModelInput:       modelInput,
		ParsedModel:      parsedModel,
		IntroTextRAA:     introTextRAA,
		BuiltinRiskRules: builtinRiskRules,
		CustomRiskRules:  customRiskRules,
	}, nil
}

func applyRiskGeneration(parsedModel *types.Model, rules types.RiskRules,
	skipRiskRules []string,
	progressReporter types.ProgressReporter) {
	progressReporter.Info("Applying risk generation")

	skippedRules := make(map[string]bool)
	if len(skipRiskRules) > 0 {
		for _, id := range skipRiskRules {
			skippedRules[id] = true
		}
	}

	for id, rule := range rules {
		_, ok := skippedRules[id]
		if ok {
			progressReporter.Infof("Skipping risk rule: %v", id)
			delete(skippedRules, id)
			continue
		}

		parsedModel.AddToListOfSupportedTags(rule.SupportedTags())
		newRisks, riskError := rule.GenerateRisks(parsedModel)
		if riskError != nil {
			progressReporter.Warnf("Error generating risks for %q: %v", id, riskError)
			continue
		}

		if len(newRisks) > 0 {
			parsedModel.GeneratedRisksByCategory[id] = newRisks
		}
	}

	if len(skippedRules) > 0 {
		keys := make([]string, 0)
		for k := range skippedRules {
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			progressReporter.Infof("Unknown risk rules to skip: %v", keys)
		}
	}

	// save also in map keyed by synthetic risk-id
	for _, category := range types.SortedRiskCategories(parsedModel) {
		someRisks := types.SortedRisksOfCategory(parsedModel, category)
		for _, risk := range someRisks {
			parsedModel.GeneratedRisksBySyntheticId[strings.ToLower(risk.SyntheticId)] = risk
		}
	}
}

func applyRAA(parsedModel *types.Model, binFolder, raaPlugin string, progressReporter types.ProgressReporter) string {
	progressReporter.Infof("Applying RAA calculation: %v", raaPlugin)

	runner, loadError := new(runner).Load(filepath.Join(binFolder, raaPlugin))
	if loadError != nil {
		progressReporter.Warnf("raa %q not loaded: %v\n", raaPlugin, loadError)
		return ""
	}

	runError := runner.Run(parsedModel, parsedModel)
	if runError != nil {
		progressReporter.Warnf("raa %q not applied: %v\n", raaPlugin, runError)
		return ""
	}

	return runner.ErrorOutput
}
