package threagile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

type Config struct {
	BuildTimestamp string
	Verbose        bool
	Interactive    bool

	AppFolder    string
	DataFolder   string
	OutputFolder string
	ServerFolder string
	TempFolder   string
	KeyFolder    string

	InputFile                   string
	DataFlowDiagramFilenamePNG  string
	DataAssetDiagramFilenamePNG string
	DataFlowDiagramFilenameDOT  string
	DataAssetDiagramFilenameDOT string
	ReportFilename              string
	ExcelRisksFilename          string
	ExcelTagsFilename           string
	JsonRisksFilename           string
	JsonTechnicalAssetsFilename string
	JsonStatsFilename           string
	TemplateFilename            string
	TechnologyFilename          string

	RiskRulesPlugins  []string
	SkipRiskRules     []string
	ExecuteModelMacro string
	RiskExcel         riskExcelConfig

	ServerMode               bool
	DiagramDPI               int
	ServerPort               int
	GraphvizDPI              int
	MaxGraphvizDPI           int
	BackupHistoryFilesToKeep int

	AddModelTitle              bool
	KeepDiagramSourceFiles     bool
	IgnoreOrphanedRiskTracking bool

	Attractiveness Attractiveness
}

type riskExcelConfig struct {
	HideColumns    []string
	SortByColumns  []string
	WidthOfColumns map[string]float64
}

func (c *Config) Defaults(buildTimestamp string) *Config {
	*c = Config{
		BuildTimestamp: buildTimestamp,
		Verbose:        false,
		Interactive:    false,

		AppFolder:    AppDir,
		DataFolder:   DataDir,
		OutputFolder: OutputDir,
		ServerFolder: ServerDir,
		TempFolder:   TempDir,
		KeyFolder:    KeyDir,

		InputFile:                   InputFile,
		DataFlowDiagramFilenamePNG:  DataFlowDiagramFilenamePNG,
		DataAssetDiagramFilenamePNG: DataAssetDiagramFilenamePNG,
		DataFlowDiagramFilenameDOT:  DataFlowDiagramFilenameDOT,
		DataAssetDiagramFilenameDOT: DataAssetDiagramFilenameDOT,
		ReportFilename:              ReportFilename,
		ExcelRisksFilename:          ExcelRisksFilename,
		ExcelTagsFilename:           ExcelTagsFilename,
		JsonRisksFilename:           JsonRisksFilename,
		JsonTechnicalAssetsFilename: JsonTechnicalAssetsFilename,
		JsonStatsFilename:           JsonStatsFilename,
		TemplateFilename:            TemplateFilename,
		TechnologyFilename:          "",

		RiskRulesPlugins:  make([]string, 0),
		SkipRiskRules:     make([]string, 0),
		ExecuteModelMacro: "",
		RiskExcel: riskExcelConfig{
			HideColumns:   make([]string, 0),
			SortByColumns: make([]string, 0),
		},

		ServerMode:               false,
		DiagramDPI:               DefaultDiagramDPI,
		ServerPort:               DefaultServerPort,
		GraphvizDPI:              DefaultGraphvizDPI,
		MaxGraphvizDPI:           MaxGraphvizDPI,
		BackupHistoryFilesToKeep: DefaultBackupHistoryFilesToKeep,

		AddModelTitle:              false,
		KeepDiagramSourceFiles:     false,
		IgnoreOrphanedRiskTracking: false,

		Attractiveness: Attractiveness{
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
	parseError := json.Unmarshal(data, &values)
	if parseError != nil {
		return fmt.Errorf("failed to parse config file %q: %w", configFilename, parseError)
	}

	var config Config
	unmarshalError := json.Unmarshal(data, &config)
	if unmarshalError != nil {
		return fmt.Errorf("failed to parse config file %q: %w", configFilename, unmarshalError)
	}

	c.Merge(config, values)

	errorList := make([]error, 0)
	c.TempFolder = c.CleanPath(c.TempFolder)
	tempDirError := os.MkdirAll(c.TempFolder, 0700)
	if tempDirError != nil {
		errorList = append(errorList, fmt.Errorf("failed to create temp dir %q: %w", c.TempFolder, tempDirError))
	}

	c.OutputFolder = c.CleanPath(c.OutputFolder)
	outDirError := os.MkdirAll(c.OutputFolder, 0700)
	if outDirError != nil {
		errorList = append(errorList, fmt.Errorf("failed to create output dir %q: %w", c.OutputFolder, outDirError))
	}

	c.AppFolder = c.CleanPath(c.AppFolder)
	appDirError := c.checkDir(c.AppFolder, "app")
	if appDirError != nil {
		errorList = append(errorList, appDirError)
	}

	c.DataFolder = c.CleanPath(c.DataFolder)
	dataDirError := c.checkDir(c.DataFolder, "data")
	if dataDirError != nil {
		errorList = append(errorList, dataDirError)
	}

	if c.TechnologyFilename != "" {
		c.TechnologyFilename = c.CleanPath(c.TechnologyFilename)
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
	if c.ServerMode {
		c.ServerFolder = c.CleanPath(c.ServerFolder)
		serverDirError := c.checkDir(c.ServerFolder, "server")
		if serverDirError != nil {
			return serverDirError
		}

		keyDirError := os.MkdirAll(filepath.Join(c.ServerFolder, c.KeyFolder), 0700)
		if keyDirError != nil {
			return fmt.Errorf("failed to create key dir %q: %v", filepath.Join(c.ServerFolder, c.KeyFolder), keyDirError)
		}
	}

	return nil
}

func (c *Config) Merge(config Config, values map[string]any) {
	for key := range values {
		switch strings.ToLower(key) {
		case strings.ToLower("Verbose"):
			c.Verbose = config.Verbose

		case strings.ToLower("AppFolder"):
			c.AppFolder = config.AppFolder

		case strings.ToLower("DataFolder"):
			c.DataFolder = config.DataFolder

		case strings.ToLower("OutputFolder"):
			c.OutputFolder = config.OutputFolder

		case strings.ToLower("ServerFolder"):
			c.ServerFolder = config.ServerFolder

		case strings.ToLower("TempFolder"):
			c.TempFolder = config.TempFolder

		case strings.ToLower("KeyFolder"):
			c.KeyFolder = config.KeyFolder

		case strings.ToLower("InputFile"):
			c.InputFile = config.InputFile

		case strings.ToLower("DataFlowDiagramFilenamePNG"):
			c.DataFlowDiagramFilenamePNG = config.DataFlowDiagramFilenamePNG

		case strings.ToLower("DataAssetDiagramFilenamePNG"):
			c.DataAssetDiagramFilenamePNG = config.DataAssetDiagramFilenamePNG

		case strings.ToLower("DataFlowDiagramFilenameDOT"):
			c.DataFlowDiagramFilenameDOT = config.DataFlowDiagramFilenameDOT

		case strings.ToLower("DataAssetDiagramFilenameDOT"):
			c.DataAssetDiagramFilenameDOT = config.DataAssetDiagramFilenameDOT

		case strings.ToLower("ReportFilename"):
			c.ReportFilename = config.ReportFilename

		case strings.ToLower("ExcelRisksFilename"):
			c.ExcelRisksFilename = config.ExcelRisksFilename

		case strings.ToLower("ExcelTagsFilename"):
			c.ExcelTagsFilename = config.ExcelTagsFilename

		case strings.ToLower("JsonRisksFilename"):
			c.JsonRisksFilename = config.JsonRisksFilename

		case strings.ToLower("JsonTechnicalAssetsFilename"):
			c.JsonTechnicalAssetsFilename = config.JsonTechnicalAssetsFilename

		case strings.ToLower("JsonStatsFilename"):
			c.JsonStatsFilename = config.JsonStatsFilename

		case strings.ToLower("TemplateFilename"):
			c.TemplateFilename = config.TemplateFilename

		case strings.ToLower("TechnologyFilename"):
			c.TechnologyFilename = config.TechnologyFilename

		case strings.ToLower("RiskRulesPlugins"):
			c.RiskRulesPlugins = config.RiskRulesPlugins

		case strings.ToLower("RiskExcel"):
			configMap, mapOk := values[key].(map[string]any)
			if !mapOk {
				continue
			}

			for valueName := range configMap {
				switch strings.ToLower(valueName) {
				case strings.ToLower("HideColumns"):
					c.RiskExcel.HideColumns = append(c.RiskExcel.HideColumns, config.RiskExcel.HideColumns...)

				case strings.ToLower("SortByColumns"):
					c.RiskExcel.SortByColumns = append(c.RiskExcel.SortByColumns, config.RiskExcel.SortByColumns...)

				case strings.ToLower("WidthOfColumns"):
					if c.RiskExcel.WidthOfColumns == nil {
						c.RiskExcel.WidthOfColumns = make(map[string]float64)
					}

					for name, value := range config.RiskExcel.WidthOfColumns {
						c.RiskExcel.WidthOfColumns[name] = value
					}
				}
			}

		case strings.ToLower("SkipRiskRules"):
			c.SkipRiskRules = config.SkipRiskRules

		case strings.ToLower("ExecuteModelMacro"):
			c.ExecuteModelMacro = config.ExecuteModelMacro

		case strings.ToLower("DiagramDPI"):
			c.DiagramDPI = config.DiagramDPI

		case strings.ToLower("ServerPort"):
			c.ServerPort = config.ServerPort

		case strings.ToLower("GraphvizDPI"):
			c.GraphvizDPI = config.GraphvizDPI

		case strings.ToLower("MaxGraphvizDPI"):
			c.MaxGraphvizDPI = config.MaxGraphvizDPI

		case strings.ToLower("BackupHistoryFilesToKeep"):
			c.BackupHistoryFilesToKeep = config.BackupHistoryFilesToKeep

		case strings.ToLower("AddModelTitle"):
			c.AddModelTitle = config.AddModelTitle

		case strings.ToLower("KeepDiagramSourceFiles"):
			c.KeepDiagramSourceFiles = config.KeepDiagramSourceFiles

		case strings.ToLower("IgnoreOrphanedRiskTracking"):
			c.IgnoreOrphanedRiskTracking = config.IgnoreOrphanedRiskTracking

		case strings.ToLower("Attractiveness"):
			c.Attractiveness = config.Attractiveness
		}
	}
}

func (c *Config) CleanPath(path string) string {
	return filepath.Clean(c.ExpandPath(path))
}

func (c *Config) checkDir(dir string, name string) error {
	dirInfo, dirError := os.Stat(dir)
	if dirError != nil {
		return fmt.Errorf("%v folder %q not good: %v", name, dir, dirError)
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
	return c.BuildTimestamp
}

func (c *Config) GetVerbose() bool {
	return c.Verbose
}

func (c *Config) GetAppFolder() string {
	return c.AppFolder
}

func (c *Config) GetDataFolder() string {
	return c.DataFolder
}

func (c *Config) GetOutputFolder() string {
	return c.OutputFolder
}

func (c *Config) GetServerFolder() string {
	return c.ServerFolder
}

func (c *Config) GetTempFolder() string {
	return c.TempFolder
}

func (c *Config) GetKeyFolder() string {
	return c.KeyFolder
}

func (c *Config) GetTechnologyFilename() string {
	return c.TechnologyFilename
}

func (c *Config) GetInputFile() string {
	return c.InputFile
}

func (c *Config) GetDataFlowDiagramFilenamePNG() string {
	return c.DataFlowDiagramFilenamePNG
}

func (c *Config) GetDataAssetDiagramFilenamePNG() string {
	return c.DataAssetDiagramFilenamePNG
}

func (c *Config) GetDataFlowDiagramFilenameDOT() string {
	return c.DataFlowDiagramFilenameDOT
}

func (c *Config) GetDataAssetDiagramFilenameDOT() string {
	return c.DataAssetDiagramFilenameDOT
}

func (c *Config) GetReportFilename() string {
	return c.ReportFilename
}

func (c *Config) GetExcelRisksFilename() string {
	return c.ExcelRisksFilename
}

func (c *Config) GetExcelTagsFilename() string {
	return c.ExcelTagsFilename
}

func (c *Config) GetJsonRisksFilename() string {
	return c.JsonRisksFilename
}

func (c *Config) GetJsonTechnicalAssetsFilename() string {
	return c.JsonTechnicalAssetsFilename
}

func (c *Config) GetJsonStatsFilename() string {
	return c.JsonStatsFilename
}

func (c *Config) GetTemplateFilename() string {
	return c.TemplateFilename
}

func (c *Config) GetRiskRulesPlugins() []string {
	return c.RiskRulesPlugins
}

func (c *Config) GetSkipRiskRules() []string {
	return c.SkipRiskRules
}

func (c *Config) GetExecuteModelMacro() string {
	return c.ExecuteModelMacro
}

func (c *Config) GetRiskExcelConfigHideColumns() []string {
	return c.RiskExcel.HideColumns
}

func (c *Config) GetRiskExcelConfigSortByColumns() []string {
	return c.RiskExcel.SortByColumns
}

func (c *Config) GetRiskExcelConfigWidthOfColumns() map[string]float64 {
	return c.RiskExcel.WidthOfColumns
}

func (c *Config) GetServerMode() bool {
	return c.ServerMode
}

func (c *Config) GetDiagramDPI() int {
	return c.DiagramDPI
}

func (c *Config) GetServerPort() int {
	return c.ServerPort
}

func (c *Config) GetGraphvizDPI() int {
	return c.GraphvizDPI
}

func (c *Config) GetMinGraphvizDPI() int {
	return MinGraphvizDPI
}

func (c *Config) GetMaxGraphvizDPI() int {
	return c.MaxGraphvizDPI
}

func (c *Config) GetBackupHistoryFilesToKeep() int {
	return c.BackupHistoryFilesToKeep
}

func (c *Config) GetAddModelTitle() bool {
	return c.AddModelTitle
}

func (c *Config) GetKeepDiagramSourceFiles() bool {
	return c.KeepDiagramSourceFiles
}

func (c *Config) GetIgnoreOrphanedRiskTracking() bool {
	return c.IgnoreOrphanedRiskTracking
}

func (c *Config) GetThreagileVersion() string {
	return ThreagileVersion
}

func (c *Config) GetProgressReporter() types.ProgressReporter {
	return DefaultProgressReporter{Verbose: c.Verbose}
}
