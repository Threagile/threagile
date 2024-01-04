/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package threagile

var verboseFlag *bool
var appDirFlag, binDirFlag, outputDirFlag, tempDirFlag *string
var inputFileFlag, raaPluginFlag *string
var serverPortFlag *int
var serverDirFlag *string

var skipRiskRulesFlag, customRiskRulesPluginFlag *string
var ignoreOrphandedRiskTrackingFlag *bool
var templateFileNameFlag *string
var diagramDpiFlag *int

var generateDataFlowDiagramFlag, generateDataAssetDiagramFlag, generateRisksJSONFlag,
	generateTechnicalAssetsJSONFlag, generateStatsJSONFlag, generateRisksExcelFlag,
	generateTagsExcelFlag, generateReportPDFFlag *bool

const verboseFlagName = "verbose"
const verboseFlagShorthand = "v"

const appDirFlagName = "app-dir"
const binDirFlagName = "bin-dir"
const outputFlagName = "output"
const tempDirFlagName = "temp-dir"

const serverDirFlagName = "server-dir"
const serverPortFlagName = "server-port"

const inputFileFlagName = "model"
const raaPluginFlagName = "raa-run"

const customRiskRulesPluginFlagName = "custom-risk-rules-plugin"
const diagramDpiFlagName = "diagram-dpi"
const skipRiskRulesFlagName = "skip-risk-rules"
const ignoreOrphandedRiskTrackingFlagName = "ignore-orphaned-risk-tracking"
const templateFileNameFlagName = "background"

const generateDataFlowDiagramFlagName = "generate-data-flow-diagram"
const generateDataAssetDiagramFlagName = "generate-data-asset-diagram"
const generateRisksJSONFlagName = "generate-risks-json"
const generateTechnicalAssetsJSONFlagName = "generate-technical-assets-json"
const generateStatsJSONFlagName = "generate-stats-json"
const generateRisksExcelFlagName = "generate-risks-excel"
const generateTagsExcelFlagName = "generate-tags-excel"
const generateReportPDFFlagName = "generate-report-pdf"
