package model

import (
	"github.com/threagile/threagile/pkg/types"
)

type mockConfig struct{}

func (m *mockConfig) GetBuildTimestamp() string {
	return ""
}
func (m *mockConfig) GetVerbose() bool {
	return false
}
func (m *mockConfig) GetInteractive() bool {
	return false
}
func (m *mockConfig) GetAppFolder() string {
	return ""
}
func (m *mockConfig) GetPluginFolder() string {
	return ""
}
func (m *mockConfig) GetDataFolder() string {
	return ""
}
func (m *mockConfig) GetOutputFolder() string {
	return ""
}
func (m *mockConfig) GetServerFolder() string {
	return ""
}
func (m *mockConfig) GetTempFolder() string {
	return ""
}
func (m *mockConfig) GetKeyFolder() string {
	return ""
}
func (m *mockConfig) GetTechnologyFilename() string {
	return ""
}
func (m *mockConfig) GetInputFile() string {
	return ""
}
func (m *mockConfig) GetImportedInputFile() string {
	return ""
}
func (m *mockConfig) GetDataFlowDiagramFilenamePNG() string {
	return ""
}
func (m *mockConfig) GetDataAssetDiagramFilenamePNG() string {
	return ""
}
func (m *mockConfig) GetDataFlowDiagramFilenameDOT() string {
	return ""
}
func (m *mockConfig) GetDataAssetDiagramFilenameDOT() string {
	return ""
}
func (m *mockConfig) GetReportFilename() string {
	return ""
}
func (m *mockConfig) GetExcelRisksFilename() string {
	return ""
}
func (m *mockConfig) GetExcelTagsFilename() string {
	return ""
}
func (m *mockConfig) GetJsonRisksFilename() string {
	return ""
}
func (m *mockConfig) GetJsonTechnicalAssetsFilename() string {
	return ""
}
func (m *mockConfig) GetJsonStatsFilename() string {
	return ""
}
func (m *mockConfig) GetTemplateFilename() string {
	return ""
}
func (m *mockConfig) GetRiskRulePlugins() []string { return make([]string, 0) }
func (m *mockConfig) GetSkipRiskRules() []string   { return make([]string, 0) }
func (m *mockConfig) GetExecuteModelMacro() string {
	return ""
}
func (m *mockConfig) GetRiskExcelConfigHideColumns() []string   { return make([]string, 0) }
func (m *mockConfig) GetRiskExcelConfigSortByColumns() []string { return make([]string, 0) }
func (m *mockConfig) GetRiskExcelConfigWidthOfColumns() map[string]float64 {
	return make(map[string]float64)
}
func (m *mockConfig) GetServerMode() bool {
	return false
}
func (m *mockConfig) GetServerPort() int               { return 0 }
func (m *mockConfig) GetDiagramDPI() int               { return 0 }
func (m *mockConfig) GetGraphvizDPI() int              { return 0 }
func (m *mockConfig) GetMaxGraphvizDPI() int           { return 0 }
func (m *mockConfig) GetBackupHistoryFilesToKeep() int { return 0 }
func (m *mockConfig) GetAddModelTitle() bool {
	return false
}
func (m *mockConfig) GetAddLegend() bool {
	return false
}
func (m *mockConfig) GetKeepDiagramSourceFiles() bool {
	return false
}
func (m *mockConfig) GetIgnoreOrphanedRiskTracking() bool {
	return false
}
func (m *mockConfig) GetThreagileVersion() string {
	return ""
}
func (m *mockConfig) GetProgressReporter() types.ProgressReporter { return m }

func (m *mockConfig) Info(a ...any)                  {}
func (m *mockConfig) Warn(a ...any)                  {}
func (m *mockConfig) Error(a ...any)                 {}
func (m *mockConfig) Infof(format string, a ...any)  {}
func (m *mockConfig) Warnf(format string, a ...any)  {}
func (m *mockConfig) Errorf(format string, a ...any) {}
