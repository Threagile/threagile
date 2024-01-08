/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package threagile

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/server"
)

var rootCmd = &cobra.Command{
	Use:   "threagile",
	Short: "\n" + docs.Logo,
	Long:  "\n" + docs.Logo + "\n\n" + docs.VersionText + "\n\n" + docs.Examples,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := readConfig(cmd, "buildTimestamp")
		commands := readCommands()
		progressReporter := common.DefaultProgressReporter{Verbose: cfg.Verbose}

		r, err := model.ReadAndAnalyzeModel(*cfg, progressReporter)
		if err != nil {
			cmd.Println("Failed to read and analyze model")
			return err
		}

		err = report.Generate(cfg, r, commands, progressReporter)
		if err != nil {
			cmd.Println("Failed to generate reports")
			cmd.PrintErr(err)
			return err
		}
		return nil
	},
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := readConfig(cmd, "buildTimestamp")
		server.RunServer(cfg)
		return nil
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cfg := new(common.Config).Defaults("")
	appDirFlag = rootCmd.PersistentFlags().String(appDirFlagName, cfg.AppFolder, "app folder")
	binDirFlag = rootCmd.PersistentFlags().String(binDirFlagName, cfg.BinFolder, "binary folder location")
	outputDirFlag = rootCmd.PersistentFlags().String(outputFlagName, cfg.OutputFolder, "output directory")
	tempDirFlag = rootCmd.PersistentFlags().String(tempDirFlagName, cfg.TempFolder, "temporary folder location")

	inputFileFlag = rootCmd.PersistentFlags().String(inputFileFlagName, cfg.InputFile, "input model yaml file")
	raaPluginFlag = rootCmd.PersistentFlags().String(raaPluginFlagName, cfg.RAAPlugin, "RAA calculation run file name")

	serverPortFlag = serverCmd.PersistentFlags().Int(serverPortFlagName, cfg.ServerPort, "the server port")
	serverDirFlag = serverCmd.PersistentFlags().String(serverDirFlagName, cfg.DataFolder, "base folder for server mode (default: "+common.DataDir+")")

	verboseFlag = rootCmd.PersistentFlags().BoolP(verboseFlagName, verboseFlagShorthand, cfg.Verbose, "verbose output")

	configFlag = rootCmd.PersistentFlags().String(configFlagName, "", "config file")

	customRiskRulesPluginFlag = rootCmd.PersistentFlags().String(customRiskRulesPluginFlagName, strings.Join(cfg.RiskRulesPlugins, ","), "comma-separated list of plugins file names with custom risk rules to load")
	diagramDpiFlag = rootCmd.PersistentFlags().Int(diagramDpiFlagName, cfg.DiagramDPI, "DPI used to render: maximum is "+fmt.Sprintf("%d", common.MaxGraphvizDPI)+"")
	skipRiskRulesFlag = rootCmd.PersistentFlags().String(skipRiskRulesFlagName, cfg.SkipRiskRules, "comma-separated list of risk rules (by their ID) to skip")
	ignoreOrphandedRiskTrackingFlag = rootCmd.PersistentFlags().Bool(ignoreOrphandedRiskTrackingFlagName, cfg.IgnoreOrphanedRiskTracking, "ignore orphaned risk tracking (just log them) not matching a concrete risk")
	templateFileNameFlag = rootCmd.PersistentFlags().String(templateFileNameFlagName, cfg.TemplateFilename, "background pdf file")

	generateDataFlowDiagramFlag = rootCmd.PersistentFlags().Bool(generateDataFlowDiagramFlagName, true, "generate data flow diagram")
	generateDataAssetDiagramFlag = rootCmd.PersistentFlags().Bool(generateDataAssetDiagramFlagName, true, "generate data asset diagram")
	generateRisksJSONFlag = rootCmd.PersistentFlags().Bool(generateRisksJSONFlagName, true, "generate risks json")
	generateTechnicalAssetsJSONFlag = rootCmd.PersistentFlags().Bool(generateTechnicalAssetsJSONFlagName, true, "generate technical assets json")
	generateStatsJSONFlag = rootCmd.PersistentFlags().Bool(generateStatsJSONFlagName, true, "generate stats json")
	generateRisksExcelFlag = rootCmd.PersistentFlags().Bool(generateRisksExcelFlagName, true, "generate risks excel")
	generateTagsExcelFlag = rootCmd.PersistentFlags().Bool(generateTagsExcelFlagName, true, "generate tags excel")
	generateReportPDFFlag = rootCmd.PersistentFlags().Bool(generateReportPDFFlagName, true, "generate report pdf, including diagrams")

	rootCmd.AddCommand(serverCmd)
}

func readCommands() *report.GenerateCommands {
	commands := new(report.GenerateCommands).Defaults()
	commands.DataFlowDiagram = *generateDataFlowDiagramFlag
	commands.DataAssetDiagram = *generateDataAssetDiagramFlag
	commands.RisksJSON = *generateRisksJSONFlag
	commands.StatsJSON = *generateStatsJSONFlag
	commands.TechnicalAssetsJSON = *generateTechnicalAssetsJSONFlag
	commands.RisksExcel = *generateRisksExcelFlag
	commands.TagsExcel = *generateTagsExcelFlag
	commands.ReportPDF = *generateReportPDFFlag
	return commands
}

func readConfig(cmd *cobra.Command, buildTimestamp string) *common.Config {
	cfg := new(common.Config).Defaults(buildTimestamp)
	configError := cfg.Load(*configFlag)
	if configError != nil {
		fmt.Printf("WARNING: failed to load config file %q: %v\n", *configFlag, configError)
	}

	flags := cmd.Flags()
	if isFlagOverriden(flags, serverPortFlagName) {
		cfg.ServerPort = *serverPortFlag
	}
	if isFlagOverriden(flags, serverDirFlagName) {
		cfg.ServerFolder = expandPath(*serverDirFlag)
	}

	if isFlagOverriden(flags, appDirFlagName) {
		cfg.AppFolder = expandPath(*appDirFlag)
	}
	if isFlagOverriden(flags, binDirFlagName) {
		cfg.BinFolder = expandPath(*binDirFlag)
	}
	if isFlagOverriden(flags, outputFlagName) {
		cfg.OutputFolder = expandPath(*outputDirFlag)
	}
	if isFlagOverriden(flags, tempDirFlagName) {
		cfg.TempFolder = expandPath(*tempDirFlag)
	}

	if isFlagOverriden(flags, verboseFlagName) {
		cfg.Verbose = *verboseFlag
	}

	if isFlagOverriden(flags, inputFileFlagName) {
		cfg.InputFile = expandPath(*inputFileFlag)
	}
	if isFlagOverriden(flags, raaPluginFlagName) {
		cfg.RAAPlugin = *raaPluginFlag
	}

	if isFlagOverriden(flags, customRiskRulesPluginFlagName) {
		cfg.RiskRulesPlugins = strings.Split(*customRiskRulesPluginFlag, ",")
	}
	if isFlagOverriden(flags, skipRiskRulesFlagName) {
		cfg.SkipRiskRules = *skipRiskRulesFlag
	}
	if isFlagOverriden(flags, ignoreOrphandedRiskTrackingFlagName) {
		cfg.IgnoreOrphanedRiskTracking = *ignoreOrphandedRiskTrackingFlag
	}
	if isFlagOverriden(flags, diagramDpiFlagName) {
		cfg.DiagramDPI = *diagramDpiFlag
	}
	if isFlagOverriden(flags, templateFileNameFlagName) {
		cfg.TemplateFilename = *templateFileNameFlag
	}
	return cfg
}

func isFlagOverriden(flags *pflag.FlagSet, flagName string) bool {
	flag := flags.Lookup(flagName)
	if flag == nil {
		return false
	}
	return flag.Changed
}

func expandPath(path string) string {
	home := userHomeDir()
	if strings.HasPrefix(path, "~") {
		path = strings.Replace(path, "~", home, 1)
	}

	if strings.HasPrefix(path, "$HOME") {
		path = strings.Replace(path, "$HOME", home, -1)
	}

	return path
}

func userHomeDir() string {
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
