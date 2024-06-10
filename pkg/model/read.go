package model

import (
	"fmt"
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

type configReader interface {
	GetBuildTimestamp() string
	GetVerbose() bool

	GetAppFolder() string
	GetOutputFolder() string
	GetServerFolder() string
	GetTempFolder() string
	GetKeyFolder() string

	GetInputFile() string
	GetDataFlowDiagramFilenamePNG() string
	GetDataAssetDiagramFilenamePNG() string
	GetDataAssetDiagramFilenameDOT() string
	GetReportFilename() string
	GetExcelRisksFilename() string
	GetExcelTagsFilename() string
	GetJsonRisksFilename() string
	GetJsonTechnicalAssetsFilename() string
	GetJsonStatsFilename() string
	GetTechnologyFilename() string

	GetRiskRulesPlugins() []string
	GetSkipRiskRules() []string
	GetExecuteModelMacro() string

	GetServerPort() int
	GetGraphvizDPI() int

	GetKeepDiagramSourceFiles() bool
	GetIgnoreOrphanedRiskTracking() bool
}

func ReadAndAnalyzeModel(config configReader, builtinRiskRules types.RiskRules, progressReporter types.ProgressReporter) (*ReadResult, error) {
	progressReporter.Infof("Writing into output directory: %v", config.GetOutputFolder())
	progressReporter.Infof("Parsing model: %v", config.GetInputFile())

	customRiskRules := LoadCustomRiskRules(config.GetRiskRulesPlugins(), progressReporter)

	modelInput := new(input.Model).Defaults()
	loadError := modelInput.Load(config.GetInputFile())
	if loadError != nil {
		return nil, fmt.Errorf("unable to load model yaml: %v", loadError)
	}

	parsedModel, parseError := ParseModel(config, modelInput, builtinRiskRules, customRiskRules)
	if parseError != nil {
		return nil, fmt.Errorf("unable to parse model yaml: %v", parseError)
	}

	introTextRAA := applyRAA(parsedModel, progressReporter)

	applyRiskGeneration(parsedModel, builtinRiskRules.Merge(customRiskRules), config.GetSkipRiskRules(), progressReporter)
	err := parsedModel.ApplyWildcardRiskTrackingEvaluation(config.GetIgnoreOrphanedRiskTracking(), progressReporter)
	if err != nil {
		return nil, fmt.Errorf("unable to apply wildcard risk tracking evaluation: %v", err)
	}

	err = parsedModel.CheckRiskTracking(config.GetIgnoreOrphanedRiskTracking(), progressReporter)
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
	for _, category := range parsedModel.SortedRiskCategories() {
		someRisks := parsedModel.SortedRisksOfCategory(category)
		for _, risk := range someRisks {
			parsedModel.GeneratedRisksBySyntheticId[strings.ToLower(risk.SyntheticId)] = risk
		}
	}
}
