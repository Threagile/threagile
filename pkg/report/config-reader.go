package report

import "github.com/threagile/threagile/pkg/types"

type configReader interface {
	GetBuildTimestamp() string
	GetThreagileVersion() string

	GetAppFolder() string
	GetOutputFolder() string
	GetTempFolder() string

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
	GetReportLogoImagePath() string

	GetSkipRiskRules() []string
	GetRiskExcelConfigHideColumns() []string
	GetRiskExcelConfigSortByColumns() []string
	GetRiskExcelConfigWidthOfColumns() map[string]float64
	GetRiskExcelWrapText() bool
	GetRiskExcelShrinkColumnsToFit() bool
	GetRiskExcelColorText() bool

	GetDiagramDPI() int
	GetMinGraphvizDPI() int
	GetMaxGraphvizDPI() int

	GetKeepDiagramSourceFiles() bool
	GetAddModelTitle() bool
	GetAddLegend() bool
	GetReportConfigurationHideChapters() map[ChaptersToShowHide]bool
	GetProgressReporter() types.ProgressReporter
}

