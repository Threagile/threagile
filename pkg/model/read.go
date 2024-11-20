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
	GetInteractive() bool
	GetAppFolder() string
	GetPluginFolder() string
	GetDataFolder() string
	GetOutputFolder() string
	GetServerFolder() string
	GetTempFolder() string
	GetKeyFolder() string
	GetInputFile() string
	GetDataFlowDiagramFilenamePNG() string
	GetDataAssetDiagramFilenamePNG() string
	GetDataFlowDiagramFilenameDOT() string
	GetDataAssetDiagramFilenameDOT() string
	GetReportFilename() string
	GetExcelRisksFilename() string
	GetExcelTagsFilename() string
	GetJsonRisksFilename() string
	GetJsonTechnicalAssetsFilename() string
	GetJsonStatsFilename() string
	GetTemplateFilename() string
	GetTechnologyFilename() string
	GetRiskRulePlugins() []string
	GetSkipRiskRules() []string
	GetExecuteModelMacro() string
	GetRiskExcelConfigHideColumns() []string
	GetRiskExcelConfigSortByColumns() []string
	GetRiskExcelConfigWidthOfColumns() map[string]float64
	GetServerMode() bool
	GetDiagramDPI() int
	GetServerPort() int
	GetGraphvizDPI() int
	GetMaxGraphvizDPI() int
	GetBackupHistoryFilesToKeep() int
	GetAddModelTitle() bool
	GetKeepDiagramSourceFiles() bool
	GetIgnoreOrphanedRiskTracking() bool
	GetThreagileVersion() string
	GetProgressReporter() types.ProgressReporter
}

func ReadAndAnalyzeModel(config configReader, builtinRiskRules types.RiskRules, progressReporter types.ProgressReporter) (*ReadResult, error) {
	progressReporter.Infof("Writing into output directory: %v", config.GetOutputFolder())
	progressReporter.Infof("Parsing model: %v", config.GetInputFile())

	customRiskRules := LoadCustomRiskRules(config.GetPluginFolder(), config.GetRiskRulePlugins(), progressReporter)

	modelInput := new(input.Model).Defaults()
	loadError := modelInput.Load(config.GetInputFile())
	if loadError != nil {
		return nil, fmt.Errorf("unable to load model yaml: %w", loadError)
	}

	return AnalyzeModel(modelInput, config, builtinRiskRules, customRiskRules, progressReporter)
}

func AnalyzeModel(modelInput *input.Model, config configReader, builtinRiskRules types.RiskRules, customRiskRules types.RiskRules, progressReporter types.ProgressReporter) (*ReadResult, error) {

	parsedModel, parseError := ParseModel(config, modelInput, builtinRiskRules, customRiskRules)
	if parseError != nil {
		return nil, fmt.Errorf("unable to parse model yaml: %w", parseError)
	}

	introTextRAA := applyRAA(parsedModel, progressReporter)

	applyRiskGeneration(parsedModel, builtinRiskRules.Merge(customRiskRules), config.GetSkipRiskRules(), progressReporter)
	err := parsedModel.ApplyWildcardRiskTrackingEvaluation(config.GetIgnoreOrphanedRiskTracking(), progressReporter)
	if err != nil {
		return nil, fmt.Errorf("unable to apply wildcard risk tracking evaluation: %w", err)
	}

	err = parsedModel.CheckRiskTracking(config.GetIgnoreOrphanedRiskTracking(), progressReporter)
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
