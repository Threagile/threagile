package threagile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/threagile/threagile/pkg/security/types"
)

type Config struct {
	buildTimestamp string
	verbose        bool
	Interactive    bool

	appFolder    string
	pluginFolder string
	dataFolder   string
	outputFolder string
	serverFolder string
	tempFolder   string
	keyFolder    string

	inputFile                   string
	dataFlowDiagramFilenamePNG  string
	dataAssetDiagramFilenamePNG string
	dataFlowDiagramFilenameDOT  string
	dataAssetDiagramFilenameDOT string
	reportFilename              string
	excelRisksFilename          string
	excelTagsFilename           string
	jsonRisksFilename           string
	jsonTechnicalAssetsFilename string
	jsonStatsFilename           string
	templateFilename            string
	technologyFilename          string

	riskRulesPlugins  []string
	skipRiskRules     []string
	executeModelMacro string
	RiskExcel         riskExcelConfig

	serverMode               bool
	diagramDPI               int
	serverPort               int
	graphvizDPI              int
	maxGraphvizDPI           int
	backupHistoryFilesToKeep int

	addModelTitle              bool
	keepDiagramSourceFiles     bool
	ignoreOrphanedRiskTracking bool

	Attractiveness Attractiveness
}

type riskExcelConfig struct {
	HideColumns    []string
	SortByColumns  []string
	WidthOfColumns map[string]float64
}

func (c *Config) Defaults(buildTimestamp string) *Config {
	*c = Config{
		buildTimestamp: buildTimestamp,
		verbose:        false,
		Interactive:    false,

		appFolder:    AppDir,
		pluginFolder: PluginDir,
		dataFolder:   DataDir,
		outputFolder: OutputDir,
		serverFolder: ServerDir,
		tempFolder:   TempDir,
		keyFolder:    KeyDir,

		inputFile:                   InputFile,
		dataFlowDiagramFilenamePNG:  DataFlowDiagramFilenamePNG,
		dataAssetDiagramFilenamePNG: DataAssetDiagramFilenamePNG,
		dataFlowDiagramFilenameDOT:  DataFlowDiagramFilenameDOT,
		dataAssetDiagramFilenameDOT: DataAssetDiagramFilenameDOT,
		reportFilename:              ReportFilename,
		excelRisksFilename:          ExcelRisksFilename,
		excelTagsFilename:           ExcelTagsFilename,
		jsonRisksFilename:           JsonRisksFilename,
		jsonTechnicalAssetsFilename: JsonTechnicalAssetsFilename,
		jsonStatsFilename:           JsonStatsFilename,
		templateFilename:            TemplateFilename,
		technologyFilename:          "",

		riskRulesPlugins:  make([]string, 0),
		skipRiskRules:     make([]string, 0),
		executeModelMacro: "",
		RiskExcel: riskExcelConfig{
			HideColumns:   make([]string, 0),
			SortByColumns: make([]string, 0),
		},

		serverMode:               false,
		diagramDPI:               DefaultDiagramDPI,
		serverPort:               DefaultServerPort,
		graphvizDPI:              DefaultGraphvizDPI,
		maxGraphvizDPI:           MaxGraphvizDPI,
		backupHistoryFilesToKeep: DefaultBackupHistoryFilesToKeep,

		addModelTitle:              false,
		keepDiagramSourceFiles:     false,
		ignoreOrphanedRiskTracking: false,

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
	c.tempFolder = c.CleanPath(c.tempFolder)
	tempDirError := os.MkdirAll(c.tempFolder, 0700)
	if tempDirError != nil {
		errorList = append(errorList, fmt.Errorf("failed to create temp dir %q: %w", c.TempFolder(), tempDirError))
	}

	c.outputFolder = c.CleanPath(c.outputFolder)
	outDirError := os.MkdirAll(c.outputFolder, 0700)
	if outDirError != nil {
		errorList = append(errorList, fmt.Errorf("failed to create output dir %q: %w", c.OutputFolder(), outDirError))
	}

	c.appFolder = c.CleanPath(c.appFolder)
	appDirError := c.checkDir(c.appFolder, "app")
	if appDirError != nil {
		errorList = append(errorList, appDirError)
	}

	c.pluginFolder = c.CleanPath(c.pluginFolder)
	pluginDirError := c.checkDir(c.pluginFolder, "plugin")
	if pluginDirError != nil {
		errorList = append(errorList, pluginDirError)
	}

	c.dataFolder = c.CleanPath(c.dataFolder)
	dataDirError := c.checkDir(c.dataFolder, "data")
	if dataDirError != nil {
		errorList = append(errorList, dataDirError)
	}

	c.technologyFilename = c.CleanPath(c.technologyFilename)

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
	if c.serverMode {
		c.serverFolder = c.CleanPath(c.serverFolder)
		serverDirError := c.checkDir(c.serverFolder, "server")
		if serverDirError != nil {
			return serverDirError
		}

		keyDirError := os.MkdirAll(filepath.Join(c.serverFolder, c.keyFolder), 0700)
		if keyDirError != nil {
			return fmt.Errorf("failed to create key dir %q: %v", filepath.Join(c.serverFolder, c.keyFolder), keyDirError)
		}
	}

	return nil
}

func (c *Config) Merge(config Config, values map[string]any) {
	for key := range values {
		switch strings.ToLower(key) {
		case strings.ToLower("Verbose"):
			c.verbose = config.verbose

		case strings.ToLower("AppFolder"):
			c.appFolder = config.appFolder

		case strings.ToLower("PluginFolder"):
			c.pluginFolder = config.pluginFolder

		case strings.ToLower("DataFolder"):
			c.dataFolder = config.dataFolder

		case strings.ToLower("OutputFolder"):
			c.outputFolder = config.outputFolder

		case strings.ToLower("ServerFolder"):
			c.serverFolder = config.serverFolder

		case strings.ToLower("TempFolder"):
			c.tempFolder = config.tempFolder

		case strings.ToLower("KeyFolder"):
			c.keyFolder = config.keyFolder

		case strings.ToLower("InputFile"):
			c.inputFile = config.inputFile

		case strings.ToLower("DataFlowDiagramFilenamePNG"):
			c.dataFlowDiagramFilenamePNG = config.dataFlowDiagramFilenamePNG

		case strings.ToLower("DataAssetDiagramFilenamePNG"):
			c.dataAssetDiagramFilenamePNG = config.dataAssetDiagramFilenamePNG

		case strings.ToLower("DataFlowDiagramFilenameDOT"):
			c.dataFlowDiagramFilenameDOT = config.dataFlowDiagramFilenameDOT

		case strings.ToLower("DataAssetDiagramFilenameDOT"):
			c.dataAssetDiagramFilenameDOT = config.dataAssetDiagramFilenameDOT

		case strings.ToLower("ReportFilename"):
			c.reportFilename = config.reportFilename

		case strings.ToLower("ExcelRisksFilename"):
			c.excelRisksFilename = config.excelRisksFilename

		case strings.ToLower("ExcelTagsFilename"):
			c.excelTagsFilename = config.excelTagsFilename

		case strings.ToLower("JsonRisksFilename"):
			c.jsonRisksFilename = config.jsonRisksFilename

		case strings.ToLower("JsonTechnicalAssetsFilename"):
			c.jsonTechnicalAssetsFilename = config.jsonTechnicalAssetsFilename

		case strings.ToLower("JsonStatsFilename"):
			c.jsonStatsFilename = config.jsonStatsFilename

		case strings.ToLower("TemplateFilename"):
			c.templateFilename = config.templateFilename

		case strings.ToLower("TechnologyFilename"):
			c.technologyFilename = config.technologyFilename

		case strings.ToLower("RiskRulesPlugins"):
			c.riskRulesPlugins = config.riskRulesPlugins

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
			c.skipRiskRules = config.skipRiskRules

		case strings.ToLower("ExecuteModelMacro"):
			c.executeModelMacro = config.executeModelMacro

		case strings.ToLower("DiagramDPI"):
			c.diagramDPI = config.diagramDPI

		case strings.ToLower("ServerPort"):
			c.serverPort = config.serverPort

		case strings.ToLower("GraphvizDPI"):
			c.graphvizDPI = config.graphvizDPI

		case strings.ToLower("MaxGraphvizDPI"):
			c.maxGraphvizDPI = config.maxGraphvizDPI

		case strings.ToLower("BackupHistoryFilesToKeep"):
			c.backupHistoryFilesToKeep = config.backupHistoryFilesToKeep

		case strings.ToLower("AddModelTitle"):
			c.addModelTitle = config.addModelTitle

		case strings.ToLower("KeepDiagramSourceFiles"):
			c.keepDiagramSourceFiles = config.keepDiagramSourceFiles

		case strings.ToLower("IgnoreOrphanedRiskTracking"):
			c.ignoreOrphanedRiskTracking = config.ignoreOrphanedRiskTracking

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

func (c *Config) BuildTimestamp() string {
	return c.buildTimestamp
}

func (c *Config) Verbose() bool {
	return c.verbose
}

func (c *Config) SetVerbose(verbose bool) {
	c.verbose = verbose
}

func (c *Config) AppFolder() string {
	return c.appFolder
}

func (c *Config) SetAppFolder(appFolder string) {
	c.appFolder = appFolder
}

func (c *Config) PluginFolder() string {
	return c.pluginFolder
}

func (c *Config) SetPluginFolder(pluginFolder string) {
	c.pluginFolder = pluginFolder
}

func (c *Config) DataFolder() string {
	return c.dataFolder
}

func (c *Config) OutputFolder() string {
	return c.outputFolder
}

func (c *Config) SetOutputFolder(outputFolder string) {
	c.outputFolder = outputFolder
}

func (c *Config) ServerFolder() string {
	return c.serverFolder
}

func (c *Config) SetServerFolder(serverFolder string) {
	c.serverFolder = serverFolder
}

func (c *Config) TempFolder() string {
	return c.tempFolder
}

func (c *Config) SetTempFolder(tempFolder string) {
	c.tempFolder = tempFolder
}

func (c *Config) KeyFolder() string {
	return c.keyFolder
}

func (c *Config) TechnologyFilename() string {
	return c.technologyFilename
}

func (c *Config) InputFile() string {
	return c.inputFile
}

func (c *Config) SetInputFile(inputFile string) {
	c.inputFile = inputFile
}

func (c *Config) DataFlowDiagramFilenamePNG() string {
	return c.dataFlowDiagramFilenamePNG
}

func (c *Config) DataAssetDiagramFilenamePNG() string {
	return c.dataAssetDiagramFilenamePNG
}

func (c *Config) DataFlowDiagramFilenameDOT() string {
	return c.dataFlowDiagramFilenameDOT
}

func (c *Config) DataAssetDiagramFilenameDOT() string {
	return c.dataAssetDiagramFilenameDOT
}

func (c *Config) ReportFilename() string {
	return c.reportFilename
}

func (c *Config) ExcelRisksFilename() string {
	return c.excelRisksFilename
}

func (c *Config) ExcelTagsFilename() string {
	return c.excelTagsFilename
}

func (c *Config) JsonRisksFilename() string {
	return c.jsonRisksFilename
}

func (c *Config) JsonTechnicalAssetsFilename() string {
	return c.jsonTechnicalAssetsFilename
}

func (c *Config) JsonStatsFilename() string {
	return c.jsonStatsFilename
}

func (c *Config) TemplateFilename() string {
	return c.templateFilename
}

func (c *Config) SetTemplateFilename(templateFilename string) {
	c.templateFilename = templateFilename
}

func (c *Config) RiskRulesPlugins() []string {
	return c.riskRulesPlugins
}
func (c *Config) SetRiskRulesPlugins(riskRulesPlugins []string) {
	c.riskRulesPlugins = riskRulesPlugins
}

func (c *Config) SkipRiskRules() []string {
	return c.skipRiskRules
}

func (c *Config) SetSkipRiskRules(skipRiskRules []string) {
	c.skipRiskRules = skipRiskRules
}

func (c *Config) ExecuteModelMacro() string {
	return c.executeModelMacro
}

func (c *Config) RiskExcelConfigHideColumns() []string {
	return c.RiskExcel.HideColumns
}

func (c *Config) RiskExcelConfigSortByColumns() []string {
	return c.RiskExcel.SortByColumns
}

func (c *Config) RiskExcelConfigWidthOfColumns() map[string]float64 {
	return c.RiskExcel.WidthOfColumns
}

func (c *Config) ServerMode() bool {
	return c.serverMode
}

func (c *Config) SetServerMode(serverMode bool) {
	c.serverMode = serverMode
}

func (c *Config) DiagramDPI() int {
	return c.diagramDPI
}

func (c *Config) SetDiagramDPI(diagramDPI int) {
	c.diagramDPI = diagramDPI
}

func (c *Config) ServerPort() int {
	return c.serverPort
}

func (c *Config) SetServerPort(serverPort int) {
	c.serverPort = serverPort
}

func (c *Config) GraphvizDPI() int {
	return c.graphvizDPI
}

func (c *Config) MinGraphvizDPI() int {
	return MinGraphvizDPI
}

func (c *Config) MaxGraphvizDPI() int {
	return c.maxGraphvizDPI
}

func (c *Config) BackupHistoryFilesToKeep() int {
	return c.backupHistoryFilesToKeep
}

func (c *Config) AddModelTitle() bool {
	return c.addModelTitle
}

func (c *Config) KeepDiagramSourceFiles() bool {
	return c.keepDiagramSourceFiles
}

func (c *Config) IgnoreOrphanedRiskTracking() bool {
	return c.ignoreOrphanedRiskTracking
}

func (c *Config) SetIgnoreOrphanedRiskTracking(ignoreOrphanedRiskTracking bool) {
	c.ignoreOrphanedRiskTracking = ignoreOrphanedRiskTracking
}

func (c *Config) ThreagileVersion() string {
	return ThreagileVersion
}

func (c *Config) ProgressReporter() types.ProgressReporter {
	return DefaultProgressReporter{Verbose: c.verbose}
}
