package model

import (
	"fmt"
	"path/filepath"

	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/run"
	"github.com/threagile/threagile/pkg/security/risks"
	"github.com/threagile/threagile/pkg/security/types"
)

type progressReporter interface {
	Info(a ...any)
	Warn(a ...any)
	Error(a ...any)
}

type ReadResult struct {
	ModelInput       *input.ModelInput
	ParsedModel      *types.ParsedModel
	IntroTextRAA     string
	BuiltinRiskRules map[string]types.RiskRule
	CustomRiskRules  map[string]*types.CustomRisk
}

// TODO: consider about splitting this function into smaller ones for better reusability
func ReadAndAnalyzeModel(config common.Config, progressReporter progressReporter) (*ReadResult, error) {
	progressReporter.Info("Writing into output directory:", config.OutputFolder)
	progressReporter.Info("Parsing model:", config.InputFile)

	builtinRiskRules := make(map[string]types.RiskRule)
	for _, rule := range risks.GetBuiltInRiskRules() {
		builtinRiskRules[rule.Category().Id] = rule
	}
	customRiskRules := types.LoadCustomRiskRules(config.RiskRulesPlugins, progressReporter)

	modelInput := new(input.ModelInput).Defaults()
	loadError := modelInput.Load(config.InputFile)
	if loadError != nil {
		return nil, fmt.Errorf("unable to load model yaml: %v", loadError)
	}

	parsedModel, parseError := ParseModel(modelInput, builtinRiskRules, customRiskRules)
	if parseError != nil {
		return nil, fmt.Errorf("unable to parse model yaml: %v", parseError)
	}

	introTextRAA := applyRAA(parsedModel, config.BinFolder, config.RAAPlugin, progressReporter)

	parsedModel.ApplyRiskGeneration(customRiskRules, builtinRiskRules,
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

func applyRAA(parsedModel *types.ParsedModel, binFolder, raaPlugin string, progressReporter progressReporter) string {
	progressReporter.Info("Applying RAA calculation:", raaPlugin)

	runner, loadError := new(run.Runner).Load(filepath.Join(binFolder, raaPlugin))
	if loadError != nil {
		progressReporter.Warn(fmt.Sprintf("WARNING: raa %q not loaded: %v\n", raaPlugin, loadError))
		return ""
	}

	runError := runner.Run(parsedModel, parsedModel)
	if runError != nil {
		progressReporter.Warn(fmt.Sprintf("WARNING: raa %q not applied: %v\n", raaPlugin, runError))
		return ""
	}

	return runner.ErrorOutput
}
