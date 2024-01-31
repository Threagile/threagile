/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/server"
)

func (what *Threagile) initRoot() *Threagile {
	what.rootCmd = &cobra.Command{
		Use:           "threagile",
		Short:         "\n" + docs.Logo,
		Long:          "\n" + docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp) + "\n\n" + docs.Examples,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := what.readConfig(cmd, what.buildTimestamp)
			commands := what.readCommands()
			progressReporter := common.DefaultProgressReporter{Verbose: cfg.Verbose}

			r, err := model.ReadAndAnalyzeModel(*cfg, progressReporter)
			if err != nil {
				cmd.Printf("Failed to read and analyze model: %v", err)
				return err
			}

			err = report.Generate(cfg, r, commands, progressReporter)
			if err != nil {
				cmd.Printf("Failed to generate reports: %v \n", err)
				return err
			}
			return nil
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Run server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := what.readConfig(cmd, what.buildTimestamp)
			server.RunServer(cfg)
			return nil
		},
	}

	cfg := new(common.Config).Defaults("")

	what.rootCmd.PersistentFlags().StringVar(&what.flags.appDirFlag, appDirFlagName, cfg.AppFolder, "app folder")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.binDirFlag, binDirFlagName, cfg.BinFolder, "binary folder location")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.outputDirFlag, outputFlagName, cfg.OutputFolder, "output directory")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.tempDirFlag, tempDirFlagName, cfg.TempFolder, "temporary folder location")

	what.rootCmd.PersistentFlags().StringVar(&what.flags.inputFileFlag, inputFileFlagName, cfg.InputFile, "input model yaml file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.raaPluginFlag, raaPluginFlagName, cfg.RAAPlugin, "RAA calculation run file name")

	serverCmd.PersistentFlags().IntVar(&what.flags.serverPortFlag, serverPortFlagName, cfg.ServerPort, "the server port")
	serverCmd.PersistentFlags().StringVar(&what.flags.serverDirFlag, serverDirFlagName, cfg.DataFolder, "base folder for server mode (default: "+common.DataDir+")")

	what.rootCmd.PersistentFlags().BoolVarP(&what.flags.verboseFlag, verboseFlagName, verboseFlagShorthand, cfg.Verbose, "verbose output")

	what.rootCmd.PersistentFlags().StringVar(&what.flags.configFlag, configFlagName, "", "config file")

	what.rootCmd.PersistentFlags().StringVar(&what.flags.customRiskRulesPluginFlag, customRiskRulesPluginFlagName, strings.Join(cfg.RiskRulesPlugins, ","), "comma-separated list of plugins file names with custom risk rules to load")
	what.rootCmd.PersistentFlags().IntVar(&what.flags.diagramDpiFlag, diagramDpiFlagName, cfg.DiagramDPI, "DPI used to render: maximum is "+fmt.Sprintf("%d", common.MaxGraphvizDPI)+"")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.skipRiskRulesFlag, skipRiskRulesFlagName, cfg.SkipRiskRules, "comma-separated list of risk rules (by their ID) to skip")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.ignoreOrphanedRiskTrackingFlag, ignoreOrphanedRiskTrackingFlagName, cfg.IgnoreOrphanedRiskTracking, "ignore orphaned risk tracking (just log them) not matching a concrete risk")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.templateFileNameFlag, templateFileNameFlagName, cfg.TemplateFilename, "background pdf file")

	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateDataFlowDiagramFlag, generateDataFlowDiagramFlagName, true, "generate data flow diagram")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateDataAssetDiagramFlag, generateDataAssetDiagramFlagName, true, "generate data asset diagram")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateRisksJSONFlag, generateRisksJSONFlagName, true, "generate risks json")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateTechnicalAssetsJSONFlag, generateTechnicalAssetsJSONFlagName, true, "generate technical assets json")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateStatsJSONFlag, generateStatsJSONFlagName, true, "generate stats json")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateRisksExcelFlag, generateRisksExcelFlagName, true, "generate risks excel")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateTagsExcelFlag, generateTagsExcelFlagName, true, "generate tags excel")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateReportPDFFlag, generateReportPDFFlagName, true, "generate report pdf, including diagrams")

	what.rootCmd.AddCommand(serverCmd)

	return what
}

func (what *Threagile) readCommands() *report.GenerateCommands {
	commands := new(report.GenerateCommands).Defaults()
	commands.DataFlowDiagram = what.flags.generateDataFlowDiagramFlag
	commands.DataAssetDiagram = what.flags.generateDataAssetDiagramFlag
	commands.RisksJSON = what.flags.generateRisksJSONFlag
	commands.StatsJSON = what.flags.generateStatsJSONFlag
	commands.TechnicalAssetsJSON = what.flags.generateTechnicalAssetsJSONFlag
	commands.RisksExcel = what.flags.generateRisksExcelFlag
	commands.TagsExcel = what.flags.generateTagsExcelFlag
	commands.ReportPDF = what.flags.generateReportPDFFlag
	return commands
}

func (what *Threagile) readConfig(cmd *cobra.Command, buildTimestamp string) *common.Config {
	cfg := new(common.Config).Defaults(buildTimestamp)
	configError := cfg.Load(what.flags.configFlag)
	if configError != nil {
		fmt.Printf("WARNING: failed to load config file %q: %v\n", what.flags.configFlag, configError)
	}

	flags := cmd.Flags()
	if isFlagOverridden(flags, serverPortFlagName) {
		cfg.ServerPort = what.flags.serverPortFlag
	}
	if isFlagOverridden(flags, serverDirFlagName) {
		cfg.ServerFolder = cfg.CleanPath(what.flags.serverDirFlag)
	}

	if isFlagOverridden(flags, appDirFlagName) {
		cfg.AppFolder = cfg.CleanPath(what.flags.appDirFlag)
	}
	if isFlagOverridden(flags, binDirFlagName) {
		cfg.BinFolder = cfg.CleanPath(what.flags.binDirFlag)
	}
	if isFlagOverridden(flags, outputFlagName) {
		cfg.OutputFolder = cfg.CleanPath(what.flags.outputDirFlag)
	}
	if isFlagOverridden(flags, tempDirFlagName) {
		cfg.TempFolder = cfg.CleanPath(what.flags.tempDirFlag)
	}

	if isFlagOverridden(flags, verboseFlagName) {
		cfg.Verbose = what.flags.verboseFlag
	}

	if isFlagOverridden(flags, inputFileFlagName) {
		cfg.InputFile = cfg.CleanPath(what.flags.inputFileFlag)
	}
	if isFlagOverridden(flags, raaPluginFlagName) {
		cfg.RAAPlugin = what.flags.raaPluginFlag
	}

	if isFlagOverridden(flags, customRiskRulesPluginFlagName) {
		cfg.RiskRulesPlugins = strings.Split(what.flags.customRiskRulesPluginFlag, ",")
	}
	if isFlagOverridden(flags, skipRiskRulesFlagName) {
		cfg.SkipRiskRules = what.flags.skipRiskRulesFlag
	}
	if isFlagOverridden(flags, ignoreOrphanedRiskTrackingFlagName) {
		cfg.IgnoreOrphanedRiskTracking = what.flags.ignoreOrphanedRiskTrackingFlag
	}
	if isFlagOverridden(flags, diagramDpiFlagName) {
		cfg.DiagramDPI = what.flags.diagramDpiFlag
	}
	if isFlagOverridden(flags, templateFileNameFlagName) {
		cfg.TemplateFilename = what.flags.templateFileNameFlag
	}
	return cfg
}

func isFlagOverridden(flags *pflag.FlagSet, flagName string) bool {
	flag := flags.Lookup(flagName)
	if flag == nil {
		return false
	}
	return flag.Changed
}
