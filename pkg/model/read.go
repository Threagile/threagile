package model

import (
	"fmt"
	"github.com/goccy/go-yaml"
	"os"
	"path/filepath"
	"strings"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

type ReadResult struct {
	ModelInput       *input.Model
	ParsedModel      *types.Model
	IntroTextRAA     string
	BuiltinRiskRules types.RiskRules
	CustomRiskRules  types.RiskRules
}

type explainRiskConfig interface {
}

type explainRiskReporter interface {
}

func (what ReadResult) ExplainRisk(cfg explainRiskConfig, risk string, reporter explainRiskReporter) error {
	return fmt.Errorf("not implemented")
}

// TODO: consider about splitting this function into smaller ones for better reusability

func ReadAndAnalyzeModel(config configReader, builtinRiskRules types.RiskRules) (*ReadResult, error) {
	config.GetProgressReporter().Infof("Writing into output directory: %v", config.GetOutputFolder())
	config.GetProgressReporter().Infof("Parsing model: %v", config.GetInputFile())

	customRiskRules := LoadCustomRiskRules(config.GetPluginFolder(), config.GetRiskRulePlugins(), config.GetProgressReporter())

	modelInput := new(input.Model).Defaults()
	loadError := modelInput.Load(config, config.GetInputFile())
	if loadError != nil {
		return nil, fmt.Errorf("unable to load model yaml: %w", loadError)
	}

	result, analysisError := AnalyzeModel(modelInput, config, builtinRiskRules, customRiskRules)
	if analysisError == nil {
		writeToFile("model yaml", result.ParsedModel, config.GetImportedInputFile(), config.GetProgressReporter())
	}

	return result, analysisError
}

func AnalyzeModel(modelInput *input.Model, config configReader, builtinRiskRules types.RiskRules, customRiskRules types.RiskRules) (*ReadResult, error) {

	parsedModel, parseError := ParseModel(config, modelInput, builtinRiskRules, customRiskRules)
	if parseError != nil {
		return nil, fmt.Errorf("unable to parse model yaml: %w", parseError)
	}

	introTextRAA := applyRAA(parsedModel, config.GetProgressReporter())

	applyRiskGeneration(parsedModel, builtinRiskRules.Merge(customRiskRules), config.GetSkipRiskRules(), config.GetProgressReporter())
	err := parsedModel.ApplyWildcardRiskTrackingEvaluation(config.GetIgnoreOrphanedRiskTracking(), config.GetProgressReporter())
	if err != nil {
		return nil, fmt.Errorf("unable to apply wildcard risk tracking evaluation: %w", err)
	}

	err = parsedModel.CheckRiskTracking(config.GetIgnoreOrphanedRiskTracking(), config.GetProgressReporter())
	if err != nil {
		return nil, fmt.Errorf("unable to check risk tracking: %w", err)
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
	for _, category := range parsedModel.SortedRiskCategories() {
		someRisks := parsedModel.SortedRisksOfCategory(category)
		for _, risk := range someRisks {
			parsedModel.GeneratedRisksBySyntheticId[strings.ToLower(risk.SyntheticId)] = risk
		}
	}
}

func writeToFile(name string, item any, filename string, progressReporter types.ProgressReporter) {
	if item == nil {
		return
	}

	if filename == "" {
		return
	}

	exported, exportError := yaml.Marshal(item)
	if exportError != nil {
		progressReporter.Warnf("Unable to export %v: %v", name, exportError)
		return
	}

	_ = os.MkdirAll(filepath.Dir(filename), 0750)

	writeError := os.WriteFile(filename, exported, 0600)
	if writeError != nil {
		progressReporter.Warnf("Unable to write %v to %q: %v", name, filename, writeError)
		return
	}

	progressReporter.Infof("Wrote %v to %q", name, filename)
}
