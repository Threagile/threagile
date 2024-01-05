/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package threagile

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/server"
)

var rootCmd = &cobra.Command{
	Use:   "threagile",
	Short: "\n" + docs.Logo,
	Long:  "\n" + docs.Logo + "\n\n" + docs.VersionText + "\n\n" + docs.Examples,
	RunE: func(cmd *cobra.Command, args []string) error {
		DoIt(readConfig("buildTimestamp"), readCommands())
		return nil
	},
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := readConfig("buildTimestamp")
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
	appDirFlag = rootCmd.PersistentFlags().String(appDirFlagName, common.AppDir, "app folder")
	binDirFlag = rootCmd.PersistentFlags().String(binDirFlagName, common.BinDir, "binary folder location")
	outputDirFlag = rootCmd.PersistentFlags().String(outputFlagName, common.OutputDir, "output directory")
	tempDirFlag = rootCmd.PersistentFlags().String(tempDirFlagName, common.TempDir, "temporary folder location")

	inputFileFlag = rootCmd.PersistentFlags().String(inputFileFlagName, common.InputFile, "input model yaml file")
	raaPluginFlag = rootCmd.PersistentFlags().String(raaPluginFlagName, "raa_calc", "RAA calculation run file name")

	serverPortFlag = serverCmd.PersistentFlags().Int(serverPortFlagName, common.DefaultServerPort, "the server port")
	serverDirFlag = serverCmd.PersistentFlags().String(serverDirFlagName, common.DataDir, "base folder for server mode (default: "+common.DataDir+")")

	verboseFlag = rootCmd.PersistentFlags().BoolP(verboseFlagName, verboseFlagShorthand, false, "verbose output")

	customRiskRulesPluginFlag = rootCmd.PersistentFlags().String(customRiskRulesPluginFlagName, "", "comma-separated list of plugins file names with custom risk rules to load")
	diagramDpiFlag = rootCmd.PersistentFlags().Int(diagramDpiFlagName, 0, "DPI used to render: maximum is "+fmt.Sprintf("%d", common.MaxGraphvizDPI)+"")
	skipRiskRulesFlag = rootCmd.PersistentFlags().String(skipRiskRulesFlagName, "", "comma-separated list of risk rules (by their ID) to skip")
	ignoreOrphandedRiskTrackingFlag = rootCmd.PersistentFlags().Bool(ignoreOrphandedRiskTrackingFlagName, false, "ignore orphaned risk tracking (just log them) not matching a concrete risk")
	templateFileNameFlag = rootCmd.PersistentFlags().String(templateFileNameFlagName, common.TemplateFilename, "background pdf file")

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

func readConfig(buildTimestamp string) *common.Config {
	cfg := new(common.Config).Defaults(buildTimestamp)
	cfg.ServerPort = *serverPortFlag
	cfg.ServerFolder = expandPath(*serverDirFlag)

	cfg.AppFolder = expandPath(*appDirFlag)
	cfg.BinFolder = expandPath(*binDirFlag)
	cfg.OutputFolder = expandPath(*outputDirFlag)
	cfg.TempFolder = expandPath(*tempDirFlag)

	cfg.Verbose = *verboseFlag

	cfg.InputFile = expandPath(*inputFileFlag)
	cfg.RAAPlugin = *raaPluginFlag

	cfg.RiskRulesPlugins = strings.Split(*customRiskRulesPluginFlag, ",")
	cfg.SkipRiskRules = *skipRiskRulesFlag
	cfg.IgnoreOrphanedRiskTracking = *ignoreOrphandedRiskTrackingFlag
	cfg.DiagramDPI = *diagramDpiFlag
	cfg.TemplateFilename = *templateFileNameFlag
	return cfg
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
