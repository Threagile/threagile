package threagile

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/types"
)

type Config struct {
	ConfigGetter
	ConfigSetter

	BuildTimestampValue string `json:"BuildTimestamp,omitempty" yaml:"BuildTimestamp"`
	VerboseValue        bool   `json:"Verbose,omitempty" yaml:"Verbose"`
	InteractiveValue    bool   `json:"Interactive,omitempty" yaml:"Interactive"`

	AppFolderValue    string `json:"AppFolder,omitempty" yaml:"AppFolder"`
	PluginFolderValue string `json:"PluginFolder,omitempty" yaml:"PluginFolder"`
	DataFolderValue   string `json:"DataFolder,omitempty" yaml:"DataFolder"`
	OutputFolderValue string `json:"OutputFolder,omitempty" yaml:"OutputFolder"`
	ServerFolderValue string `json:"ServerFolder,omitempty" yaml:"ServerFolder"`
	TempFolderValue   string `json:"TempFolder,omitempty" yaml:"TempFolder"`
	KeyFolderValue    string `json:"KeyFolder,omitempty" yaml:"KeyFolder"`

	InputFileValue                   string `json:"InputFile,omitempty" yaml:"InputFile"`
	ImportedInputFileValue           string `json:"ImportedInputFile,omitempty" yaml:"ImportedInputFile"`
	DataFlowDiagramFilenamePNGValue  string `json:"DataFlowDiagramFilenamePNG,omitempty" yaml:"DataFlowDiagramFilenamePNG"`
	DataAssetDiagramFilenamePNGValue string `json:"DataAssetDiagramFilenamePNG,omitempty" yaml:"DataAssetDiagramFilenamePNG"`
	DataFlowDiagramFilenameDOTValue  string `json:"DataFlowDiagramFilenameDOT,omitempty" yaml:"DataFlowDiagramFilenameDOT"`
	DataAssetDiagramFilenameDOTValue string `json:"DataAssetDiagramFilenameDOT,omitempty" yaml:"DataAssetDiagramFilenameDOT"`
	ReportFilenameValue              string `json:"ReportFilename,omitempty" yaml:"ReportFilename"`
	ExcelRisksFilenameValue          string `json:"ExcelRisksFilename,omitempty" yaml:"ExcelRisksFilename"`
	ExcelTagsFilenameValue           string `json:"ExcelTagsFilename,omitempty" yaml:"ExcelTagsFilename"`
	JsonRisksFilenameValue           string `json:"JsonRisksFilename,omitempty" yaml:"JsonRisksFilename"`
	JsonTechnicalAssetsFilenameValue string `json:"JsonTechnicalAssetsFilename,omitempty" yaml:"JsonTechnicalAssetsFilename"`
	JsonStatsFilenameValue           string `json:"JsonStatsFilename,omitempty" yaml:"JsonStatsFilename"`
	TemplateFilenameValue            string `json:"TemplateFilename,omitempty" yaml:"TemplateFilename"`
	ReportLogoImagePathValue         string `json:"ReportLogoImagePath,omitempty" yaml:"ReportLogoImagePath"`
	TechnologyFilenameValue          string `json:"TechnologyFilename,omitempty" yaml:"TechnologyFilename"`

	RiskRulePluginsValue   []string        `json:"RiskRulePlugins,omitempty" yaml:"RiskRulePlugins"`
	SkipRiskRulesValue     []string        `json:"SkipRiskRules,omitempty" yaml:"SkipRiskRules"`
	ExecuteModelMacroValue string          `json:"ExecuteModelMacro,omitempty" yaml:"ExecuteModelMacro"`
	RiskExcelValue         RiskExcelConfig `json:"RiskExcel" yaml:"RiskExcel"`

	ServerModeValue               bool `json:"ServerMode,omitempty" yaml:"ServerMode"`
	ServerPortValue               int  `json:"ServerPort,omitempty" yaml:"ServerPort"`
	DiagramDPIValue               int  `json:"DiagramDPI,omitempty" yaml:"DiagramDPI"`
	GraphvizDPIValue              int  `json:"GraphvizDPI,omitempty" yaml:"GraphvizDPI"`
	MaxGraphvizDPIValue           int  `json:"MaxGraphvizDPI,omitempty" yaml:"MaxGraphvizDPI"`
	BackupHistoryFilesToKeepValue int  `json:"BackupHistoryFilesToKeep,omitempty" yaml:"BackupHistoryFilesToKeep"`

	AddModelTitleValue              bool `json:"AddModelTitle,omitempty" yaml:"AddModelTitle"`
	AddLegendValue                  bool `json:"AddLegend,omitempty" yaml:"AddLegend"`
	KeepDiagramSourceFilesValue     bool `json:"KeepDiagramSourceFiles,omitempty" yaml:"KeepDiagramSourceFiles"`
	IgnoreOrphanedRiskTrackingValue bool `json:"IgnoreOrphanedRiskTracking,omitempty" yaml:"IgnoreOrphanedRiskTracking"`

	SkipDataFlowDiagramValue     bool `json:"SkipDataFlowDiagram,omitempty" yaml:"SkipDataFlowDiagram"`
	SkipDataAssetDiagramValue    bool `json:"SkipDataAssetDiagram,omitempty" yaml:"SkipDataAssetDiagram"`
	SkipRisksJSONValue           bool `json:"SkipRisksJSON,omitempty" yaml:"SkipRisksJSON"`
	SkipTechnicalAssetsJSONValue bool `json:"SkipTechnicalAssetsJSON,omitempty" yaml:"SkipTechnicalAssetsJSON"`
	SkipStatsJSONValue           bool `json:"SkipStatsJSON,omitempty" yaml:"SkipStatsJSON"`
	SkipRisksExcelValue          bool `json:"SkipRisksExcel,omitempty" yaml:"SkipRisksExcel"`
	SkipTagsExcelValue           bool `json:"SkipTagsExcel,omitempty" yaml:"SkipTagsExcel"`
	SkipReportPDFValue           bool `json:"SkipReportPDF,omitempty" yaml:"SkipReportPDF"`
	SkipReportADOCValue          bool `json:"SkipReportADOC,omitempty" yaml:"SkipReportADOC"`

	AttractivenessValue Attractiveness `json:"Attractiveness" yaml:"Attractiveness"`

	ReportConfigurationValue report.ReportConfiguation `json:"ReportConfiguration" yaml:"ReportConfiguration"`
}

type ConfigGetter interface {
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
	GetTechnologyFilename() string
	GetInputFile() string
	GetImportedInputFile() string
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
	GetReportLogoImagePath() string
	GetTemplateFilename() string
	GetRiskRulePlugins() []string
	GetSkipRiskRules() []string
	GetExecuteModelMacro() string
	GetRiskExcelConfigHideColumns() []string
	GetRiskExcelConfigSortByColumns() []string
	GetRiskExcelConfigWidthOfColumns() map[string]float64
	GetRiskExcelWrapText() bool
	GetRiskExcelShrinkColumnsToFit() bool
	GetRiskExcelColorText() bool
	GetServerMode() bool
	GetServerPort() int
	GetDiagramDPI() int
	GetGraphvizDPI() int
	GetMinGraphvizDPI() int
	GetMaxGraphvizDPI() int
	GetBackupHistoryFilesToKeep() int
	GetAddModelTitle() bool
	GetAddLegend() bool
	GetKeepDiagramSourceFiles() bool
	GetIgnoreOrphanedRiskTracking() bool
	GetSkipDataFlowDiagram() bool
	GetSkipDataAssetDiagram() bool
	GetSkipRisksJSON() bool
	GetSkipTechnicalAssetsJSON() bool
	GetSkipStatsJSON() bool
	GetSkipRisksExcel() bool
	GetSkipTagsExcel() bool
	GetSkipReportPDF() bool
	GetSkipReportADOC() bool
	GetAttractiveness() Attractiveness
	GetReportConfiguration() report.ReportConfiguation
	GetThreagileVersion() string
	GetProgressReporter() types.ProgressReporter
	GetReportConfigurationHideChapters() map[report.ChaptersToShowHide]bool
}
type ConfigSetter interface {
	SetVerbose(verbose bool)
	SetInteractive(interactive bool)
	SetAppFolder(appFolder string)
	SetPluginFolder(pluginFolder string)
	SetOutputFolder(outputFolder string)
	SetServerFolder(serverFolder string)
	SetTempFolder(tempFolder string)
	SetInputFile(inputFile string)
	SetTemplateFilename(templateFilename string)
	SetRiskRulePlugins(riskRulePlugins []string)
	SetSkipRiskRules(skipRiskRules []string)
	SetServerMode(serverMode bool)
	SetServerPort(serverPort int)
	SetDiagramDPI(diagramDPI int)
	SetIgnoreOrphanedRiskTracking(ignoreOrphanedRiskTracking bool)
}

func (c *Config) Defaults(buildTimestamp string) *Config {
	*c = Config{
		BuildTimestampValue: buildTimestamp,
		VerboseValue:        false,
		InteractiveValue:    false,

		AppFolderValue:    AppDir,
		PluginFolderValue: PluginDir,
		DataFolderValue:   DataDir,
		OutputFolderValue: OutputDir,
		ServerFolderValue: ServerDir,
		TempFolderValue:   TempDir,
		KeyFolderValue:    KeyDir,

		InputFileValue:                   InputFile,
		DataFlowDiagramFilenamePNGValue:  DataFlowDiagramFilenamePNG,
		DataAssetDiagramFilenamePNGValue: DataAssetDiagramFilenamePNG,
		DataFlowDiagramFilenameDOTValue:  DataFlowDiagramFilenameDOT,
		DataAssetDiagramFilenameDOTValue: DataAssetDiagramFilenameDOT,
		ReportFilenameValue:              ReportFilename,
		ExcelRisksFilenameValue:          ExcelRisksFilename,
		ExcelTagsFilenameValue:           ExcelTagsFilename,
		JsonRisksFilenameValue:           JsonRisksFilename,
		JsonTechnicalAssetsFilenameValue: JsonTechnicalAssetsFilename,
		JsonStatsFilenameValue:           JsonStatsFilename,
		TemplateFilenameValue:            TemplateFilename,
		ReportLogoImagePathValue:         ReportLogoImagePath,
		TechnologyFilenameValue:          "",

		RiskRulePluginsValue:   make([]string, 0),
		SkipRiskRulesValue:     make([]string, 0),
		ExecuteModelMacroValue: "",
		RiskExcelValue: RiskExcelConfig{
			HideColumns:        make([]string, 0),
			SortByColumns:      make([]string, 0),
			WidthOfColumns:     make(map[string]float64),
			ShrinkColumnsToFit: true,
			WrapText:           false,
			ColorText:          true,
		},

		ServerModeValue:               false,
		DiagramDPIValue:               DefaultDiagramDPI,
		ServerPortValue:               DefaultServerPort,
		GraphvizDPIValue:              DefaultGraphvizDPI,
		MaxGraphvizDPIValue:           MaxGraphvizDPI,
		BackupHistoryFilesToKeepValue: DefaultBackupHistoryFilesToKeep,

		AddModelTitleValue:              false,
		AddLegendValue:                  false,
		KeepDiagramSourceFilesValue:     false,
		IgnoreOrphanedRiskTrackingValue: false,

		AttractivenessValue: Attractiveness{
			Quantity: 0,
			Confidentiality: AttackerFocus{
				Asset:                 0,
				ProcessedOrStoredData: 0,
				TransferredData:       0,
			},
			Integrity: AttackerFocus{
				Asset:                 0,
				ProcessedOrStoredData: 0,
				TransferredData:       0,
			},
			Availability: AttackerFocus{
				Asset:                 0,
				ProcessedOrStoredData: 0,
				TransferredData:       0,
			},
		},

		ReportConfigurationValue: report.ReportConfiguation{
			HideChapter: make(map[report.ChaptersToShowHide]bool),
		},
	}

	return c
}

func (c *Config) Load(configFilename string) error {
	if len(configFilename) == 0 {
		return nil
	}

	data, readError := os.ReadFile(filepath.Clean(configFilename))
	if readError != nil {
		return readError
	}

	values := make(map[string]any)
	var config Config

	if strings.HasSuffix(configFilename, ".yaml") {
		parseError := yaml.Unmarshal(data, &values)
		if parseError != nil {
			return fmt.Errorf("failed to parse keys of yaml config file %q: %w", configFilename, parseError)
		}

		unmarshalError := yaml.Unmarshal(data, &config)
		if unmarshalError != nil {
			return fmt.Errorf("failed to parse yaml config file %q: %w", configFilename, unmarshalError)
		}
	} else {
		parseError := json.Unmarshal(data, &values)
		if parseError != nil {
			return fmt.Errorf("failed to parse keys of json config file %q: %w", configFilename, parseError)
		}

		unmarshalError := json.Unmarshal(data, &config)
		if unmarshalError != nil {
			return fmt.Errorf("failed to parse json config file %q: %w", configFilename, unmarshalError)
		}
	}

	c.Merge(config, values)

	errorList := make([]error, 0)
	c.TempFolderValue = c.CleanPath(c.TempFolderValue)
	tempDirError := os.MkdirAll(c.TempFolderValue, 0700)
	if tempDirError != nil {
		errorList = append(errorList, fmt.Errorf("failed to create temp dir %q: %w", c.TempFolderValue, tempDirError))
	}

	c.OutputFolderValue = c.CleanPath(c.OutputFolderValue)
	outDirError := os.MkdirAll(c.OutputFolderValue, 0700)
	if outDirError != nil {
		errorList = append(errorList, fmt.Errorf("failed to create output dir %q: %w", c.OutputFolderValue, outDirError))
	}

	c.AppFolderValue = c.CleanPath(c.AppFolderValue)
	appDirError := c.checkDir(c.AppFolderValue, "app")
	if appDirError != nil {
		errorList = append(errorList, appDirError)
	}

	c.PluginFolderValue = c.CleanPath(c.PluginFolderValue)
	pluginDirError := c.checkDir(c.PluginFolderValue, "plugin")
	if pluginDirError != nil {
		errorList = append(errorList, pluginDirError)
	}

	c.DataFolderValue = c.CleanPath(c.DataFolderValue)
	dataDirError := c.checkDir(c.DataFolderValue, "data")
	if dataDirError != nil {
		errorList = append(errorList, dataDirError)
	}

	if c.TechnologyFilenameValue != "" {
		c.TechnologyFilenameValue = c.CleanPath(c.TechnologyFilenameValue)
	}

	serverFolderError := c.CheckServerFolder()
	if serverFolderError != nil {
		errorList = append(errorList, serverFolderError)
	}

	if len(errorList) > 0 {
		return errors.Join(errorList...)
	}

	return nil
}

func (c *Config) CheckServerFolder() error {
	if c.ServerModeValue {
		c.ServerFolderValue = c.CleanPath(c.ServerFolderValue)
		serverDirError := c.checkDir(c.ServerFolderValue, "server")
		if serverDirError != nil {
			return serverDirError
		}

		keyDirError := os.MkdirAll(filepath.Join(c.ServerFolderValue, c.KeyFolderValue), 0700)
		if keyDirError != nil {
			return fmt.Errorf("failed to create key dir %q: %w", filepath.Join(c.ServerFolderValue, c.KeyFolderValue), keyDirError)
		}
	}

	return nil
}

func (c *Config) Merge(config Config, values map[string]any) {
	for key := range values {
		switch strings.ToLower(key) {
		case strings.ToLower("BuildTimestamp"):
			c.BuildTimestampValue = config.BuildTimestampValue

		case strings.ToLower("Verbose"):
			c.VerboseValue = config.VerboseValue

		case strings.ToLower("Interactive"):
			c.InteractiveValue = config.InteractiveValue

		case strings.ToLower("AppFolder"):
			c.AppFolderValue = config.AppFolderValue

		case strings.ToLower("PluginFolder"):
			c.PluginFolderValue = config.PluginFolderValue

		case strings.ToLower("DataFolder"):
			c.DataFolderValue = config.DataFolderValue

		case strings.ToLower("OutputFolder"):
			c.OutputFolderValue = config.OutputFolderValue

		case strings.ToLower("ServerFolder"):
			c.ServerFolderValue = config.ServerFolderValue

		case strings.ToLower("TempFolder"):
			c.TempFolderValue = config.TempFolderValue

		case strings.ToLower("KeyFolder"):
			c.KeyFolderValue = config.KeyFolderValue

		case strings.ToLower("InputFile"):
			c.InputFileValue = config.InputFileValue

		case strings.ToLower("DataFlowDiagramFilenamePNG"):
			c.DataFlowDiagramFilenamePNGValue = config.DataFlowDiagramFilenamePNGValue

		case strings.ToLower("DataAssetDiagramFilenamePNG"):
			c.DataAssetDiagramFilenamePNGValue = config.DataAssetDiagramFilenamePNGValue

		case strings.ToLower("DataFlowDiagramFilenameDOT"):
			c.DataFlowDiagramFilenameDOTValue = config.DataFlowDiagramFilenameDOTValue

		case strings.ToLower("DataAssetDiagramFilenameDOT"):
			c.DataAssetDiagramFilenameDOTValue = config.DataAssetDiagramFilenameDOTValue

		case strings.ToLower("ReportFilename"):
			c.ReportFilenameValue = config.ReportFilenameValue

		case strings.ToLower("ExcelRisksFilename"):
			c.ExcelRisksFilenameValue = config.ExcelRisksFilenameValue

		case strings.ToLower("ExcelTagsFilename"):
			c.ExcelTagsFilenameValue = config.ExcelTagsFilenameValue

		case strings.ToLower("JsonRisksFilename"):
			c.JsonRisksFilenameValue = config.JsonRisksFilenameValue

		case strings.ToLower("JsonTechnicalAssetsFilename"):
			c.JsonTechnicalAssetsFilenameValue = config.JsonTechnicalAssetsFilenameValue

		case strings.ToLower("JsonStatsFilename"):
			c.JsonStatsFilenameValue = config.JsonStatsFilenameValue

		case strings.ToLower("TemplateFilename"):
			c.TemplateFilenameValue = config.TemplateFilenameValue

		case strings.ToLower("ReportLogoImagePath"):
			c.ReportLogoImagePathValue = config.ReportLogoImagePathValue

		case strings.ToLower("TechnologyFilename"):
			c.TechnologyFilenameValue = config.TechnologyFilenameValue

		case strings.ToLower("RiskRulePlugins"):
			c.RiskRulePluginsValue = config.RiskRulePluginsValue

		case strings.ToLower("SkipRiskRules"):
			c.SkipRiskRulesValue = config.SkipRiskRulesValue

		case strings.ToLower("ExecuteModelMacro"):
			c.ExecuteModelMacroValue = config.ExecuteModelMacroValue

		case strings.ToLower("RiskExcel"):
			configMap, mapOk := values[key].(map[string]any)
			if !mapOk {
				continue
			}

			for valueName := range configMap {
				switch strings.ToLower(valueName) {
				case strings.ToLower("HideColumns"):
					c.RiskExcelValue.HideColumns = append(c.RiskExcelValue.HideColumns, config.RiskExcelValue.HideColumns...)

				case strings.ToLower("SortByColumns"):
					c.RiskExcelValue.SortByColumns = append(c.RiskExcelValue.SortByColumns, config.RiskExcelValue.SortByColumns...)

				case strings.ToLower("WidthOfColumns"):
					if c.RiskExcelValue.WidthOfColumns == nil {
						c.RiskExcelValue.WidthOfColumns = make(map[string]float64)
					}

					for name, value := range config.RiskExcelValue.WidthOfColumns {
						c.RiskExcelValue.WidthOfColumns[name] = value
					}

				case strings.ToLower("ShrinkColumnsToFit"):
					c.RiskExcelValue.ShrinkColumnsToFit = config.RiskExcelValue.ShrinkColumnsToFit

				case strings.ToLower("WrapText"):
					c.RiskExcelValue.WrapText = config.RiskExcelValue.WrapText

				case strings.ToLower("ColorText"):
					c.RiskExcelValue.ColorText = config.RiskExcelValue.ColorText
				}
			}

		case strings.ToLower("ServerMode"):
			c.ServerModeValue = config.ServerModeValue

		case strings.ToLower("DiagramDPI"):
			c.DiagramDPIValue = config.DiagramDPIValue

		case strings.ToLower("ServerPort"):
			c.ServerPortValue = config.ServerPortValue

		case strings.ToLower("GraphvizDPI"):
			c.GraphvizDPIValue = config.GraphvizDPIValue

		case strings.ToLower("MaxGraphvizDPI"):
			c.MaxGraphvizDPIValue = config.MaxGraphvizDPIValue

		case strings.ToLower("BackupHistoryFilesToKeep"):
			c.BackupHistoryFilesToKeepValue = config.BackupHistoryFilesToKeepValue

		case strings.ToLower("AddModelTitle"):
			c.AddModelTitleValue = config.AddModelTitleValue

		case strings.ToLower("AddLegend"):
			c.AddLegendValue = config.AddLegendValue

		case strings.ToLower("KeepDiagramSourceFiles"):
			c.KeepDiagramSourceFilesValue = config.KeepDiagramSourceFilesValue

		case strings.ToLower("IgnoreOrphanedRiskTracking"):
			c.IgnoreOrphanedRiskTrackingValue = config.IgnoreOrphanedRiskTrackingValue

		case strings.ToLower("Attractiveness"):
			c.AttractivenessValue = config.AttractivenessValue

		case strings.ToLower("ReportConfiguration"):
			configMap, mapOk := values[key].(map[string]any)
			if !mapOk {
				continue
			}

			for valueName := range configMap {
				switch strings.ToLower(valueName) {
				case strings.ToLower("HideChapter"):
					if c.ReportConfigurationValue.HideChapter == nil {
						c.ReportConfigurationValue.HideChapter = make(map[report.ChaptersToShowHide]bool)
					}

					for chapter, value := range config.ReportConfigurationValue.HideChapter {
						c.ReportConfigurationValue.HideChapter[chapter] = value
						if value {
							log.Println("Hiding chapter: ", chapter)
						}
					}
				}
			}
		}
	}
}

func (c *Config) CleanPath(path string) string {
	return filepath.Clean(c.ExpandPath(path))
}

func (c *Config) checkDir(dir string, name string) error {
	dirInfo, dirError := os.Stat(dir)
	if dirError != nil {
		return fmt.Errorf("%v folder %q not good: %w", name, dir, dirError)
	}

	if !dirInfo.IsDir() {
		return fmt.Errorf("%v folder %q is not a folder", name, dir)
	}

	return nil
}

func (c *Config) ExpandPath(path string) string {
	home := c.UserHomeDir()
	if strings.HasPrefix(path, "~") {
		path = strings.Replace(path, "~", home, 1)
	}

	if strings.HasPrefix(path, "$HOME") {
		path = strings.Replace(path, "$HOME", home, -1)
	}

	return path
}

func (c *Config) UserHomeDir() string {
	switch runtime.GOOS {
	case "windows":
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home

	default:
		return os.Getenv("HOME")
	}
}

func (c *Config) GetBuildTimestamp() string {
	return c.BuildTimestampValue
}

func (c *Config) GetVerbose() bool {
	return c.VerboseValue
}

func (c *Config) SetVerbose(verbose bool) {
	c.VerboseValue = verbose
}

func (c *Config) GetInteractive() bool {
	return c.InteractiveValue
}

func (c *Config) SetInteractive(interactive bool) {
	c.InteractiveValue = interactive
}

func (c *Config) GetAppFolder() string {
	return c.AppFolderValue
}

func (c *Config) SetAppFolder(appFolder string) {
	c.AppFolderValue = appFolder
}

func (c *Config) GetPluginFolder() string {
	return c.PluginFolderValue
}

func (c *Config) SetPluginFolder(pluginFolder string) {
	c.PluginFolderValue = pluginFolder
}

func (c *Config) GetDataFolder() string {
	return c.DataFolderValue
}

func (c *Config) GetOutputFolder() string {
	return c.OutputFolderValue
}

func (c *Config) SetOutputFolder(outputFolder string) {
	c.OutputFolderValue = outputFolder
}

func (c *Config) GetServerFolder() string {
	return c.ServerFolderValue
}

func (c *Config) SetServerFolder(serverFolder string) {
	c.ServerFolderValue = serverFolder
}

func (c *Config) GetTempFolder() string {
	return c.TempFolderValue
}

func (c *Config) SetTempFolder(tempFolder string) {
	c.TempFolderValue = tempFolder
}

func (c *Config) GetKeyFolder() string {
	return c.KeyFolderValue
}

func (c *Config) GetTechnologyFilename() string {
	return c.TechnologyFilenameValue
}

func (c *Config) GetInputFile() string {
	return c.InputFileValue
}

func (c *Config) GetImportedInputFile() string {
	return c.ImportedInputFileValue
}

func (c *Config) SetInputFile(inputFile string) {
	c.InputFileValue = inputFile
}

func (c *Config) GetDataFlowDiagramFilenamePNG() string {
	return c.DataFlowDiagramFilenamePNGValue
}

func (c *Config) GetDataAssetDiagramFilenamePNG() string {
	return c.DataAssetDiagramFilenamePNGValue
}

func (c *Config) GetDataFlowDiagramFilenameDOT() string {
	return c.DataFlowDiagramFilenameDOTValue
}

func (c *Config) GetDataAssetDiagramFilenameDOT() string {
	return c.DataAssetDiagramFilenameDOTValue
}

func (c *Config) GetReportFilename() string {
	return c.ReportFilenameValue
}

func (c *Config) GetExcelRisksFilename() string {
	return c.ExcelRisksFilenameValue
}

func (c *Config) GetExcelTagsFilename() string {
	return c.ExcelTagsFilenameValue
}

func (c *Config) GetJsonRisksFilename() string {
	return c.JsonRisksFilenameValue
}

func (c *Config) GetJsonTechnicalAssetsFilename() string {
	return c.JsonTechnicalAssetsFilenameValue
}

func (c *Config) GetJsonStatsFilename() string {
	return c.JsonStatsFilenameValue
}

func (c *Config) GetReportLogoImagePath() string {
	return c.ReportLogoImagePathValue
}

func (c *Config) GetTemplateFilename() string {
	return c.TemplateFilenameValue
}

func (c *Config) SetTemplateFilename(templateFilename string) {
	c.TemplateFilenameValue = templateFilename
}

func (c *Config) GetRiskRulePlugins() []string {
	return c.RiskRulePluginsValue
}

func (c *Config) SetRiskRulePlugins(riskRulePlugins []string) {
	c.RiskRulePluginsValue = riskRulePlugins
}

func (c *Config) GetSkipRiskRules() []string {
	return c.SkipRiskRulesValue
}

func (c *Config) SetSkipRiskRules(skipRiskRules []string) {
	c.SkipRiskRulesValue = skipRiskRules
}

func (c *Config) GetExecuteModelMacro() string {
	return c.ExecuteModelMacroValue
}

func (c *Config) GetRiskExcelConfigHideColumns() []string {
	return c.RiskExcelValue.HideColumns
}

func (c *Config) GetRiskExcelConfigSortByColumns() []string {
	return c.RiskExcelValue.SortByColumns
}

func (c *Config) GetRiskExcelConfigWidthOfColumns() map[string]float64 {
	return c.RiskExcelValue.WidthOfColumns
}

func (c *Config) GetRiskExcelWrapText() bool {
	return c.RiskExcelValue.WrapText
}

func (c *Config) GetRiskExcelShrinkColumnsToFit() bool {
	return c.RiskExcelValue.ShrinkColumnsToFit
}

func (c *Config) GetRiskExcelColorText() bool {
	return c.RiskExcelValue.ColorText
}

func (c *Config) GetServerMode() bool {
	return c.ServerModeValue
}

func (c *Config) SetServerMode(serverMode bool) {
	c.ServerModeValue = serverMode
}

func (c *Config) GetServerPort() int {
	return c.ServerPortValue
}

func (c *Config) SetServerPort(serverPort int) {
	c.ServerPortValue = serverPort
}

func (c *Config) GetDiagramDPI() int {
	return c.DiagramDPIValue
}

func (c *Config) SetDiagramDPI(diagramDPI int) {
	c.DiagramDPIValue = diagramDPI
}

func (c *Config) GetGraphvizDPI() int {
	return c.GraphvizDPIValue
}

func (c *Config) GetMinGraphvizDPI() int {
	return MinGraphvizDPI
}

func (c *Config) GetMaxGraphvizDPI() int {
	return c.MaxGraphvizDPIValue
}

func (c *Config) GetBackupHistoryFilesToKeep() int {
	return c.BackupHistoryFilesToKeepValue
}

func (c *Config) GetAddModelTitle() bool {
	return c.AddModelTitleValue
}

func (c *Config) GetAddLegend() bool {
	return c.AddLegendValue
}

func (c *Config) GetKeepDiagramSourceFiles() bool {
	return c.KeepDiagramSourceFilesValue
}

func (c *Config) GetIgnoreOrphanedRiskTracking() bool {
	return c.IgnoreOrphanedRiskTrackingValue
}

func (c *Config) SetIgnoreOrphanedRiskTracking(ignoreOrphanedRiskTracking bool) {
	c.IgnoreOrphanedRiskTrackingValue = ignoreOrphanedRiskTracking
}

func (c *Config) GetSkipDataFlowDiagram() bool {
	return c.SkipDataFlowDiagramValue
}

func (c *Config) GetSkipDataAssetDiagram() bool {
	return c.SkipDataAssetDiagramValue
}

func (c *Config) GetSkipRisksJSON() bool {
	return c.SkipRisksJSONValue
}

func (c *Config) GetSkipTechnicalAssetsJSON() bool {
	return c.SkipTechnicalAssetsJSONValue
}

func (c *Config) GetSkipStatsJSON() bool {
	return c.SkipStatsJSONValue
}

func (c *Config) GetSkipRisksExcel() bool {
	return c.SkipRisksExcelValue
}

func (c *Config) GetSkipTagsExcel() bool {
	return c.SkipTagsExcelValue
}

func (c *Config) GetSkipReportPDF() bool {
	return c.SkipReportPDFValue
}

func (c *Config) GetSkipReportADOC() bool {
	return c.SkipReportADOCValue
}

func (c *Config) GetAttractiveness() Attractiveness {
	return c.AttractivenessValue
}

func (c *Config) GetReportConfiguration() report.ReportConfiguation {
	return c.ReportConfigurationValue
}

func (c *Config) GetThreagileVersion() string {
	return ThreagileVersion
}

func (c *Config) GetProgressReporter() types.ProgressReporter {
	return DefaultProgressReporter{Verbose: c.VerboseValue}
}

func (c *Config) GetReportConfigurationHideChapters() map[report.ChaptersToShowHide]bool {
	return c.ReportConfigurationValue.HideChapter
}
