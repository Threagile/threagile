/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

const (
	configFlagName = "config"

	interactiveFlagName      = "interactive"
	interactiveFlagShorthand = "i"

	verboseFlagName      = "verbose"
	verboseFlagShorthand = "v"

	appDirFlagName    = "app-dir"
	pluginDirFlagName = "plugin-dir"
	outputFlagName    = "output"
	tempDirFlagName   = "temp-dir"

	serverDirFlagName  = "server-dir"
	serverPortFlagName = "server-port"

	inputFileFlagName = "model"
	raaPluginFlagName = "raa-run"

	customRiskRulesPluginFlagName      = "custom-risk-rules-plugin"
	diagramDpiFlagName                 = "diagram-dpi"
	skipRiskRulesFlagName              = "skip-risk-rules"
	ignoreOrphanedRiskTrackingFlagName = "ignore-orphaned-risk-tracking"
	templateFileNameFlagName           = "background"

	generateDataFlowDiagramFlagName     = "generate-data-flow-diagram"
	generateDataAssetDiagramFlagName    = "generate-data-asset-diagram"
	generateRisksJSONFlagName           = "generate-risks-json"
	generateTechnicalAssetsJSONFlagName = "generate-technical-assets-json"
	generateStatsJSONFlagName           = "generate-stats-json"
	generateRisksExcelFlagName          = "generate-risks-excel"
	generateTagsExcelFlagName           = "generate-tags-excel"
	generateReportPDFFlagName           = "generate-report-pdf"
)

type Flags struct {
	configFlag      string
	verboseFlag     bool
	interactiveFlag bool
	appDirFlag      string
	pluginDirFlag   string
	outputDirFlag   string
	tempDirFlag     string
	inputFileFlag   string
	raaPluginFlag   string
	serverPortFlag  int
	serverDirFlag   string

	skipRiskRulesFlag              string
	customRiskRulesPluginFlag      string
	ignoreOrphanedRiskTrackingFlag bool
	templateFileNameFlag           string
	diagramDpiFlag                 int

	generateDataFlowDiagramFlag     bool
	generateDataAssetDiagramFlag    bool
	generateRisksJSONFlag           bool
	generateTechnicalAssetsJSONFlag bool
	generateStatsJSONFlag           bool
	generateRisksExcelFlag          bool
	generateTagsExcelFlag           bool
	generateReportPDFFlag           bool
}
