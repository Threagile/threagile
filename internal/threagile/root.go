/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
	"github.com/mattn/go-shellwords"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/report"
)

const (
	UsageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
 {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Title "help"))}}
  {{rpad .Title .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}
`
)

func (what *Threagile) initRoot() *Threagile {
	what.rootCmd = &cobra.Command{
		Use:           "threagile",
		Version:       ThreagileVersion,
		Short:         "\n" + Logo,
		Long:          "\n" + Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp) + "\n\n" + Examples,
		SilenceErrors: true,
		SilenceUsage:  true,
		Run:           what.run,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	what.config = new(Config).Defaults(what.buildTimestamp)
	return what.initFlags()
}

func (what *Threagile) initFlags() *Threagile {
	what.rootCmd.ResetFlags()

	what.rootCmd.PersistentFlags().StringVar(&what.flags.configFlag, configFlagName, "", "config file")

	what.rootCmd.PersistentFlags().BoolVarP(&what.flags.VerboseValue, verboseFlagName, verboseFlagShorthand, what.config.GetVerbose(), "Verbose output")
	what.rootCmd.PersistentFlags().BoolVarP(&what.flags.InteractiveValue, interactiveFlagName, interactiveFlagShorthand, what.config.GetInteractive(), "interactive mode")

	what.rootCmd.PersistentFlags().StringVar(&what.flags.AppFolderValue, appDirFlagName, what.config.GetAppFolder(), "app folder")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.PluginFolderValue, pluginDirFlagName, what.config.GetPluginFolder(), "plugin directory")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.DataFolderValue, dataDirFlagName, what.config.GetDataFolder(), "data directory")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.OutputFolderValue, outputFlagName, what.config.GetOutputFolder(), "output directory")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.TempFolderValue, tempDirFlagName, what.config.GetTempFolder(), "temporary folder location")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.KeyFolderValue, keyDirFlagName, what.config.GetKeyFolder(), "key folder location")

	what.rootCmd.PersistentFlags().StringVar(&what.flags.InputFileValue, inputFileFlagName, what.config.GetInputFile(), "input model yaml file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.ImportedInputFileValue, importedFileFlagName, what.config.GetImportedInputFile(), "imported input model yaml file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.DataFlowDiagramFilenamePNGValue, dataFlowDiagramPNGFileFlagName, what.config.GetDataFlowDiagramFilenamePNG(), "data flow diagram PNG file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.DataAssetDiagramFilenamePNGValue, dataAssetDiagramPNGFileFlagName, what.config.GetDataAssetDiagramFilenamePNG(), "data asset diagram PNG file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.DataFlowDiagramFilenameDOTValue, dataFlowDiagramDOTFileFlagName, what.config.GetDataFlowDiagramFilenameDOT(), "data flow diagram DOT file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.DataAssetDiagramFilenameDOTValue, dataAssetDiagramDOTFileFlagName, what.config.GetDataAssetDiagramFilenameDOT(), "data asset diagram DOT file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.ReportFilenameValue, reportFileFlagName, what.config.GetReportFilename(), "report file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.ExcelRisksFilenameValue, risksExcelFileFlagName, what.config.GetExcelRisksFilename(), "risks Excel file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.ExcelTagsFilenameValue, tagsExcelFileFlagName, what.config.GetExcelTagsFilename(), "tags Excel file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.JsonRisksFilenameValue, risksJsonFileFlagName, what.config.GetJsonRisksFilename(), "risks JSON file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.JsonTechnicalAssetsFilenameValue, technicalAssetsJsonFileFlagName, what.config.GetJsonTechnicalAssetsFilename(), "technical assets JSON file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.JsonStatsFilenameValue, statsJsonFileFlagName, what.config.GetJsonStatsFilename(), "stats JSON file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.TemplateFilenameValue, templateFileNameFlagName, what.config.GetTemplateFilename(), "template pdf file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.ReportLogoImagePathValue, reportLogoImagePathFlagName, what.config.GetReportLogoImagePath(), "report logo image")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.TechnologyFilenameValue, technologyFileFlagName, what.config.GetTechnologyFilename(), "file name of additional technologies")

	what.rootCmd.PersistentFlags().StringVar(&what.flags.riskRulePluginsValue, customRiskRulesPluginFlagName, strings.Join(what.config.GetRiskRulePlugins(), ","), "comma-separated list of plugins file names with custom risk rules to load")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.skipRiskRulesValue, skipRiskRulesFlagName, strings.Join(what.config.GetSkipRiskRules(), ","), "comma-separated list of risk rules (by their ID) to skip")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.ExecuteModelMacroValue, executeModelMacroFlagName, what.config.GetExecuteModelMacro(), "macro to execute")

	// RiskExcelValue not available as flags

	what.rootCmd.PersistentFlags().IntVar(&what.flags.ServerPortValue, serverPortFlagName, what.config.GetServerPort(), "server port")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.ServerFolderValue, serverDirFlagName, what.config.GetDataFolder(), "base folder for server mode (default: "+DataDir+")")
	what.rootCmd.PersistentFlags().IntVar(&what.flags.DiagramDPIValue, diagramDpiFlagName, what.config.GetDiagramDPI(), "DPI used to render: maximum is "+fmt.Sprintf("%d", what.config.GetMaxGraphvizDPI())+"")
	// MaxGraphvizDPIValue not available as flags
	what.rootCmd.PersistentFlags().IntVar(&what.flags.BackupHistoryFilesToKeepValue, backupHistoryFilesToKeepFlagName, what.config.GetBackupHistoryFilesToKeep(), "number of backup history files to keep")

	what.rootCmd.PersistentFlags().BoolVar(&what.flags.AddModelTitleValue, addModelTitleFlagName, what.config.GetAddModelTitle(), "add model title")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.KeepDiagramSourceFilesValue, keepDiagramSourceFilesFlagName, what.config.GetKeepDiagramSourceFiles(), "keep diagram source files")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.IgnoreOrphanedRiskTrackingValue, ignoreOrphanedRiskTrackingFlagName, what.config.GetIgnoreOrphanedRiskTracking(), "ignore orphaned risk tracking (just log them) not matching a concrete risk")

	what.rootCmd.PersistentFlags().BoolVar(&what.flags.SkipDataFlowDiagramValue, skipDataFlowDiagramFlagName, what.config.GetSkipDataFlowDiagram(), "skip generating data flow diagram")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.SkipDataAssetDiagramValue, skipDataAssetDiagramFlagName, what.config.GetSkipDataAssetDiagram(), "skip generating data asset diagram")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.SkipRisksJSONValue, skipRisksJSONFlagName, what.config.GetSkipRisksJSON(), "skip generating risks json")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.SkipTechnicalAssetsJSONValue, skipTechnicalAssetsJSONFlagName, what.config.GetSkipTechnicalAssetsJSON(), "skip generating technical assets json")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.SkipStatsJSONValue, skipStatsJSONFlagName, what.config.GetSkipStatsJSON(), "skip generating stats json")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.SkipRisksExcelValue, skipRisksExcelFlagName, what.config.GetSkipRisksExcel(), "skip generating risks excel")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.SkipTagsExcelValue, skipTagsExcelFlagName, what.config.GetSkipTagsExcel(), "skip generating tags excel")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.SkipReportPDFValue, skipReportPDFFlagName, what.config.GetSkipReportPDF(), "skip generating report pdf, including diagrams")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.SkipReportADOCValue, skipReportADOCFlagName, what.config.GetSkipReportADOC(), "skip generating report adoc, including diagrams")

	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateDataFlowDiagramFlag, generateDataFlowDiagramFlagName, !what.config.GetSkipDataFlowDiagram(), "(deprecated) generate generating data flow diagram")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateDataAssetDiagramFlag, generateDataAssetDiagramFlagName, !what.config.GetSkipDataAssetDiagram(), "(deprecated) generate generating data asset diagram")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateRisksJSONFlag, generateRisksJSONFlagName, !what.config.GetSkipRisksJSON(), "(deprecated) generate generating risks json")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateTechnicalAssetsJSONFlag, generateTechnicalAssetsJSONFlagName, !what.config.GetSkipTechnicalAssetsJSON(), "(deprecated) generate generating technical assets json")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateStatsJSONFlag, generateStatsJSONFlagName, !what.config.GetSkipStatsJSON(), "(deprecated) generate generating stats json")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateRisksExcelFlag, generateRisksExcelFlagName, !what.config.GetSkipRisksExcel(), "(deprecated) generate generating risks excel")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateTagsExcelFlag, generateTagsExcelFlagName, !what.config.GetSkipTagsExcel(), "(deprecated) generate generating tags excel")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateReportPDFFlag, generateReportPDFFlagName, !what.config.GetSkipReportPDF(), "(deprecated) generate generating report pdf, including diagrams")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateReportADOCFlag, generateReportADOCFlagName, !what.config.GetSkipReportADOC(), "(deprecated) generate generating report adoc, including diagrams")

	// AttractivenessValue not available as flags
	// ReportConfigurationValue not available as flags
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.MapElevatedToHighValue, mapElevatedToHighFlagName, what.config.GetMapElevatedToHigh(), "map elevated severity to high severity")

	return what
}

func (what *Threagile) run(thisCmd *cobra.Command, args []string) {
	what.processArgs(thisCmd, args)

	if !what.config.GetInteractive() {
		what.rootCmd.Println("Please add the --interactive flag to run in interactive mode.")
		return
	}

	completer := readline.NewPrefixCompleter()
	for _, child := range what.rootCmd.Commands() {
		what.cobraToReadline(completer, child)
	}

	dir, homeError := os.UserHomeDir()
	if homeError != nil {
		what.rootCmd.Println("Error, please report bug at https://github.com/Threagile/threagile. Unable to find home directory: " + homeError.Error())
		return
	}

	shell, readlineError := readline.NewEx(&readline.Config{
		Prompt:            "\033[31m>>\033[0m ",
		HistoryFile:       filepath.Join(dir, ".threagile_history"),
		HistoryLimit:      1000,
		AutoComplete:      completer,
		InterruptPrompt:   "^C",
		EOFPrompt:         "quit",
		HistorySearchFold: true,
	})

	if readlineError != nil {
		what.rootCmd.Println("Error, please report bug at https://github.com/Threagile/threagile. Unable to initialize readline: " + readlineError.Error())
		return
	}

	defer func() { _ = shell.Close() }()

	for {
		line, readError := shell.Readline()
		if errors.Is(readError, readline.ErrInterrupt) {
			return
		}
		if readError != nil {
			what.rootCmd.Println("Error, please report bug at https://github.com/Threagile/threagile. Unable to read line: " + readError.Error())
			return
		}

		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		params, parseError := shellwords.Parse(line)
		if parseError != nil {
			what.rootCmd.Printf("failed to parse command line: %s", parseError.Error())
			continue
		}

		cmd, args, findError := what.rootCmd.Find(params)
		if findError != nil {
			what.rootCmd.Printf("failed to find command: %s", findError.Error())
			continue
		}

		if cmd == nil || cmd == what.rootCmd {
			what.rootCmd.Println("failed to find command")
			continue
		}

		flagsError := cmd.ParseFlags(args)
		if flagsError != nil {
			what.rootCmd.Printf("invalid flags: %s", flagsError.Error())
			continue
		}

		if !cmd.DisableFlagParsing {
			args = cmd.Flags().Args()
		}

		argsError := cmd.ValidateArgs(args)
		if argsError != nil {
			_ = cmd.Help()
			continue
		}

		if cmd.Run != nil {
			cmd.Run(cmd, args)
			continue
		}

		if cmd.RunE != nil {
			runError := cmd.RunE(cmd, args)
			if runError != nil {
				what.rootCmd.Printf("error: %v \n", runError)
			}

			continue
		}

		_ = cmd.Help()
	}
}

func (what *Threagile) cobraToReadline(node readline.PrefixCompleterInterface, cmd *cobra.Command) {
	cmd.SetUsageTemplate(UsageTemplate)
	cmd.Use = what.usage(cmd)
	pcItem := readline.PcItem(cmd.Use)
	node.SetChildren(append(node.GetChildren(), pcItem))

	for _, child := range cmd.Commands() {
		what.cobraToReadline(pcItem, child)
	}
}

func (what *Threagile) usage(cmd *cobra.Command) string {
	words := make([]string, 0, len(cmd.ArgAliases)+1)
	words = append(words, cmd.Use)

	for _, name := range cmd.ArgAliases {
		words = append(words, "["+name+"]")
	}

	return strings.Join(words, " ")
}

func (what *Threagile) readCommands() *report.GenerateCommands {
	commands := new(report.GenerateCommands).Defaults()
	commands.DataFlowDiagram = !what.flags.SkipDataFlowDiagramValue
	commands.DataAssetDiagram = !what.flags.SkipDataAssetDiagramValue
	commands.RisksJSON = !what.flags.SkipRisksJSONValue
	commands.StatsJSON = !what.flags.SkipStatsJSONValue
	commands.TechnicalAssetsJSON = !what.flags.SkipTechnicalAssetsJSONValue
	commands.RisksExcel = !what.flags.SkipRisksExcelValue
	commands.TagsExcel = !what.flags.SkipTagsExcelValue
	commands.ReportPDF = !what.flags.SkipReportPDFValue
	commands.ReportADOC = !what.flags.SkipReportADOCValue
	return commands
}

func (what *Threagile) processSystemArgs(cmd *cobra.Command) *Threagile {
	what.config.InteractiveValue = what.processArgs(cmd, os.Args[1:])
	return what
}

func (what *Threagile) processArgs(cmd *cobra.Command, args []string) bool {
	_ = cmd.PersistentFlags().Parse(args)

	if what.isFlagOverridden(cmd, configFlagName) {
		configError := what.config.Load(what.flags.configFlag)
		if configError != nil {
			what.rootCmd.Printf("WARNING: failed to load config file %q: %v\n", what.flags.configFlag, configError)
		}
	}

	if what.isFlagOverridden(cmd, verboseFlagName) {
		what.config.VerboseValue = what.flags.VerboseValue
	}

	interactive := what.config.GetInteractive()
	if what.isFlagOverridden(cmd, interactiveFlagName) {
		interactive = what.flags.InteractiveValue
	}

	if what.isFlagOverridden(cmd, appDirFlagName) {
		what.config.AppFolderValue = what.config.CleanPath(what.flags.AppFolderValue)
	}

	if what.isFlagOverridden(cmd, pluginDirFlagName) {
		what.config.PluginFolderValue = what.config.CleanPath(what.flags.PluginFolderValue)
	}

	if what.isFlagOverridden(cmd, dataDirFlagName) {
		what.config.DataFolderValue = what.config.CleanPath(what.flags.DataFolderValue)
	}

	if what.isFlagOverridden(cmd, outputFlagName) {
		what.config.OutputFolderValue = what.config.CleanPath(what.flags.OutputFolderValue)
	}

	if what.isFlagOverridden(cmd, serverDirFlagName) {
		what.config.ServerFolderValue = what.config.CleanPath(what.flags.ServerFolderValue)
	}

	if what.isFlagOverridden(cmd, tempDirFlagName) {
		what.config.TempFolderValue = what.config.CleanPath(what.flags.TempFolderValue)
	}

	if what.isFlagOverridden(cmd, keyDirFlagName) {
		what.config.KeyFolderValue = what.config.CleanPath(what.flags.KeyFolderValue)
	}

	if what.isFlagOverridden(cmd, importedFileFlagName) {
		what.config.ImportedInputFileValue = what.config.CleanPath(what.flags.ImportedInputFileValue)
	}

	if what.isFlagOverridden(cmd, inputFileFlagName) {
		what.config.InputFileValue = what.config.CleanPath(what.flags.InputFileValue)
	}

	if what.isFlagOverridden(cmd, dataFlowDiagramPNGFileFlagName) {
		what.config.DataFlowDiagramFilenamePNGValue = what.config.CleanPath(what.flags.DataFlowDiagramFilenamePNGValue)
	}

	if what.isFlagOverridden(cmd, dataAssetDiagramPNGFileFlagName) {
		what.config.DataAssetDiagramFilenamePNGValue = what.config.CleanPath(what.flags.DataAssetDiagramFilenamePNGValue)
	}

	if what.isFlagOverridden(cmd, dataFlowDiagramDOTFileFlagName) {
		what.config.DataFlowDiagramFilenameDOTValue = what.config.CleanPath(what.flags.DataFlowDiagramFilenameDOTValue)
	}

	if what.isFlagOverridden(cmd, dataAssetDiagramDOTFileFlagName) {
		what.config.DataAssetDiagramFilenameDOTValue = what.config.CleanPath(what.flags.DataAssetDiagramFilenameDOTValue)
	}

	if what.isFlagOverridden(cmd, reportFileFlagName) {
		what.config.ReportFilenameValue = what.config.CleanPath(what.flags.ReportFilenameValue)
	}

	if what.isFlagOverridden(cmd, risksExcelFileFlagName) {
		what.config.ExcelRisksFilenameValue = what.config.CleanPath(what.flags.ExcelRisksFilenameValue)
	}

	if what.isFlagOverridden(cmd, tagsExcelFileFlagName) {
		what.config.ExcelTagsFilenameValue = what.config.CleanPath(what.flags.ExcelTagsFilenameValue)
	}

	if what.isFlagOverridden(cmd, risksJsonFileFlagName) {
		what.config.JsonRisksFilenameValue = what.config.CleanPath(what.flags.JsonRisksFilenameValue)
	}

	if what.isFlagOverridden(cmd, technicalAssetsJsonFileFlagName) {
		what.config.JsonTechnicalAssetsFilenameValue = what.config.CleanPath(what.flags.JsonTechnicalAssetsFilenameValue)
	}

	if what.isFlagOverridden(cmd, statsJsonFileFlagName) {
		what.config.JsonStatsFilenameValue = what.config.CleanPath(what.flags.JsonStatsFilenameValue)
	}

	if what.isFlagOverridden(cmd, templateFileNameFlagName) {
		what.config.TemplateFilenameValue = what.flags.TemplateFilenameValue
	}

	if what.isFlagOverridden(cmd, reportLogoImagePathFlagName) {
		what.config.ReportLogoImagePathValue = what.flags.ReportLogoImagePathValue
	}

	if what.isFlagOverridden(cmd, technologyFileFlagName) {
		what.config.TechnologyFilenameValue = what.flags.TechnologyFilenameValue
	}

	if what.isFlagOverridden(cmd, customRiskRulesPluginFlagName) {
		what.config.RiskRulePluginsValue = strings.Split(what.flags.riskRulePluginsValue, ",")
	}

	if what.isFlagOverridden(cmd, skipRiskRulesFlagName) {
		what.config.SkipRiskRulesValue = strings.Split(what.flags.skipRiskRulesValue, ",")
	}

	if what.isFlagOverridden(cmd, executeModelMacroFlagName) {
		what.config.ExecuteModelMacroValue = what.flags.ExecuteModelMacroValue
	}

	// RiskExcelValue not available as flags

	if what.isFlagOverridden(cmd, serverModeFlagName) {
		what.config.ServerModeValue = what.flags.ServerModeValue
	}

	if what.isFlagOverridden(cmd, serverPortFlagName) {
		what.config.ServerPortValue = what.flags.ServerPortValue
	}

	if what.isFlagOverridden(cmd, diagramDpiFlagName) {
		what.config.DiagramDPIValue = what.flags.DiagramDPIValue
	}

	if what.isFlagOverridden(cmd, graphvizDpiFlagName) {
		what.config.GraphvizDPIValue = what.flags.GraphvizDPIValue
	}

	// MaxGraphvizDPIValue not available as flags

	if what.isFlagOverridden(cmd, backupHistoryFilesToKeepFlagName) {
		what.config.BackupHistoryFilesToKeepValue = what.flags.BackupHistoryFilesToKeepValue
	}

	if what.isFlagOverridden(cmd, addModelTitleFlagName) {
		what.config.AddModelTitleValue = what.flags.AddModelTitleValue
	}

	if what.isFlagOverridden(cmd, keepDiagramSourceFilesFlagName) {
		what.config.KeepDiagramSourceFilesValue = what.flags.KeepDiagramSourceFilesValue
	}

	if what.isFlagOverridden(cmd, ignoreOrphanedRiskTrackingFlagName) {
		what.config.IgnoreOrphanedRiskTrackingValue = what.flags.IgnoreOrphanedRiskTrackingValue
	}

	if what.isFlagOverridden(cmd, skipDataFlowDiagramFlagName) {
		what.config.SkipDataFlowDiagramValue = what.flags.SkipDataFlowDiagramValue
	}

	if what.isFlagOverridden(cmd, skipDataAssetDiagramFlagName) {
		what.config.SkipDataAssetDiagramValue = what.flags.SkipDataAssetDiagramValue
	}

	if what.isFlagOverridden(cmd, skipRisksJSONFlagName) {
		what.config.SkipRisksJSONValue = what.flags.SkipRisksJSONValue
	}

	if what.isFlagOverridden(cmd, skipTechnicalAssetsJSONFlagName) {
		what.config.SkipTechnicalAssetsJSONValue = what.flags.SkipTechnicalAssetsJSONValue
	}

	if what.isFlagOverridden(cmd, skipStatsJSONFlagName) {
		what.config.SkipStatsJSONValue = what.flags.SkipStatsJSONValue
	}

	if what.isFlagOverridden(cmd, skipRisksExcelFlagName) {
		what.config.SkipRisksExcelValue = what.flags.SkipRisksExcelValue
	}

	if what.isFlagOverridden(cmd, skipTagsExcelFlagName) {
		what.config.SkipTagsExcelValue = what.flags.SkipTagsExcelValue
	}

	if what.isFlagOverridden(cmd, skipReportPDFFlagName) {
		what.config.SkipReportPDFValue = what.flags.SkipReportPDFValue
	}

	if what.isFlagOverridden(cmd, skipReportADOCFlagName) {
		what.config.SkipReportADOCValue = what.flags.SkipReportADOCValue
	}

	if what.isFlagOverridden(cmd, generateDataFlowDiagramFlagName) {
		what.config.SkipDataFlowDiagramValue = !what.flags.generateDataFlowDiagramFlag
	}

	if what.isFlagOverridden(cmd, generateDataAssetDiagramFlagName) {
		what.config.SkipDataAssetDiagramValue = !what.flags.generateDataAssetDiagramFlag
	}

	if what.isFlagOverridden(cmd, generateRisksJSONFlagName) {
		what.config.SkipRisksJSONValue = !what.flags.generateRisksJSONFlag
	}

	if what.isFlagOverridden(cmd, generateTechnicalAssetsJSONFlagName) {
		what.config.SkipTechnicalAssetsJSONValue = !what.flags.generateTechnicalAssetsJSONFlag
	}

	if what.isFlagOverridden(cmd, generateStatsJSONFlagName) {
		what.config.SkipStatsJSONValue = !what.flags.generateStatsJSONFlag
	}

	if what.isFlagOverridden(cmd, generateRisksExcelFlagName) {
		what.config.SkipRisksExcelValue = !what.flags.generateRisksExcelFlag
	}

	if what.isFlagOverridden(cmd, generateTagsExcelFlagName) {
		what.config.SkipTagsExcelValue = !what.flags.generateTagsExcelFlag
	}

	if what.isFlagOverridden(cmd, generateReportPDFFlagName) {
		what.config.SkipReportPDFValue = !what.flags.generateReportPDFFlag
	}

	if what.isFlagOverridden(cmd, generateReportADOCFlagName) {
		what.config.SkipReportADOCValue = !what.flags.generateReportADOCFlag
	}

	// AttractivenessValue not available as flags
	// ReportConfigurationValue not available as flags

	if what.isFlagOverridden(cmd, mapElevatedToHighFlagName) {
		what.config.MapElevatedToHighValue = what.flags.MapElevatedToHighValue
	}

	what.initFlags()

	return interactive
}

func (what *Threagile) isFlagOverridden(cmd *cobra.Command, flagName string) bool {
	if cmd == nil {
		return false
	}

	flag := cmd.PersistentFlags().Lookup(flagName)
	if flag == nil {
		return false
	}

	return flag.Changed
}
