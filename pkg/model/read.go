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
	ParsedModel      *types.ParsedModel
	IntroTextRAA     string
	BuiltinRiskRules map[string]risks.RiskRule
	CustomRiskRules  map[string]*CustomRisk
}

func (what ReadResult) ExplainRisk(cfg *common.Config, risk string, reporter common.DefaultProgressReporter) error {
	return fmt.Errorf("not implemented")
}

// TODO: consider about splitting this function into smaller ones for better reusability
func ReadAndAnalyzeModel(config common.Config, progressReporter types.ProgressReporter) (*ReadResult, error) {
	progressReporter.Infof("Writing into output directory: %v", config.OutputFolder)
	progressReporter.Infof("Parsing model: %v", config.InputFile)

	builtinRiskRules := make(map[string]risks.RiskRule)
	for _, rule := range risks.GetBuiltInRiskRules() {
		builtinRiskRules[rule.Category().Id] = rule
	}
	customRiskRules := LoadCustomRiskRules(config.RiskRulesPlugins, progressReporter)

	modelInput := new(input.Model).Defaults()
	loadError := modelInput.Load(config.InputFile)
	if loadError != nil {
		return nil, fmt.Errorf("unable to load model yaml: %v", loadError)
	}

	parsedModel, parseError := ParseModel(modelInput, builtinRiskRules, customRiskRules)
	if parseError != nil {
		return nil, fmt.Errorf("unable to parse model yaml: %v", parseError)
	}

	introTextRAA := applyRAA(parsedModel, config.PluginFolder, config.RAAPlugin, progressReporter)

	applyRiskGeneration(parsedModel, customRiskRules, builtinRiskRules,
		config.SkipRiskRules, progressReporter)
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

func applyRisk(parsedModel *types.ParsedModel, rule risks.RiskRule, skippedRules *map[string]bool) {
	id := rule.Category().Id
	_, ok := (*skippedRules)[id]

	if ok {
		fmt.Printf("Skipping risk rule %q\n", rule.Category().Id)
		delete(*skippedRules, rule.Category().Id)
	} else {
		parsedModel.AddToListOfSupportedTags(rule.SupportedTags())
		generatedRisks := rule.GenerateRisks(parsedModel)
		if generatedRisks != nil {
			if len(generatedRisks) > 0 {
				parsedModel.GeneratedRisksByCategory[rule.Category().Id] = generatedRisks
			}
		} else {
			fmt.Printf("Failed to generate risks for %q\n", id)
		}
	}
}

// TODO: refactor skipRiskRules to be a string array instead of a comma-separated string
func applyRiskGeneration(parsedModel *types.ParsedModel, customRiskRules map[string]*CustomRisk,
	builtinRiskRules map[string]risks.RiskRule,
	skipRiskRules string,
	progressReporter types.ProgressReporter) {
	progressReporter.Info("Applying risk generation")

	skippedRules := make(map[string]bool)
	if len(skipRiskRules) > 0 {
		for _, id := range strings.Split(skipRiskRules, ",") {
			skippedRules[id] = true
		}
	}

	for _, rule := range builtinRiskRules {
		applyRisk(parsedModel, rule, &skippedRules)
	}

	// NOW THE CUSTOM RISK RULES (if any)
	for id, customRule := range customRiskRules {
		_, ok := skippedRules[id]
		if ok {
			progressReporter.Infof("Skipping custom risk rule: %v", id)
			delete(skippedRules, id)
		} else {
			progressReporter.Infof("Executing custom risk rule: %v", id)
			parsedModel.AddToListOfSupportedTags(customRule.Tags)
			customRisks := customRule.GenerateRisks(parsedModel)
			if len(customRisks) > 0 {
				parsedModel.GeneratedRisksByCategory[customRule.Category.Id] = customRisks
			}

			progressReporter.Infof("Added custom risks: %v", len(customRisks))
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

func applyRAA(parsedModel *types.ParsedModel, binFolder, raaPlugin string, progressReporter types.ProgressReporter) string {
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
