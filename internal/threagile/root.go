/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
	"github.com/mattn/go-shellwords"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/docs"
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

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}
`
)

func (what *Threagile) initRoot() *Threagile {
	what.rootCmd = &cobra.Command{
		Use:           "threagile",
		Version:       docs.ThreagileVersion,
		Short:         "\n" + docs.Logo,
		Long:          "\n" + docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp) + "\n\n" + docs.Examples,
		SilenceErrors: true,
		SilenceUsage:  true,
		Run:           what.run,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	defaultConfig := new(common.Config).Defaults(what.buildTimestamp)

	what.rootCmd.PersistentFlags().StringVar(&what.flags.appDirFlag, appDirFlagName, defaultConfig.AppFolder, "app folder")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.pluginDirFlag, pluginDirFlagName, defaultConfig.PluginFolder, "plugin folder location")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.outputDirFlag, outputFlagName, defaultConfig.OutputFolder, "output directory")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.tempDirFlag, tempDirFlagName, defaultConfig.TempFolder, "temporary folder location")

	what.rootCmd.PersistentFlags().StringVar(&what.flags.inputFileFlag, inputFileFlagName, defaultConfig.InputFile, "input model yaml file")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.raaPluginFlag, raaPluginFlagName, defaultConfig.RAAPlugin, "RAA calculation run file name")

	what.rootCmd.PersistentFlags().BoolVarP(&what.flags.interactiveFlag, interactiveFlagName, interactiveFlagShorthand, defaultConfig.Interactive, "interactive mode")
	what.rootCmd.PersistentFlags().BoolVarP(&what.flags.verboseFlag, verboseFlagName, verboseFlagShorthand, defaultConfig.Verbose, "verbose output")

	what.rootCmd.PersistentFlags().StringVar(&what.flags.configFlag, configFlagName, "", "config file")

	what.rootCmd.PersistentFlags().StringVar(&what.flags.customRiskRulesPluginFlag, customRiskRulesPluginFlagName, strings.Join(defaultConfig.RiskRulesPlugins, ","), "comma-separated list of plugins file names with custom risk rules to load")
	what.rootCmd.PersistentFlags().IntVar(&what.flags.diagramDpiFlag, diagramDpiFlagName, defaultConfig.DiagramDPI, "DPI used to render: maximum is "+fmt.Sprintf("%d", common.MaxGraphvizDPI)+"")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.skipRiskRulesFlag, skipRiskRulesFlagName, defaultConfig.SkipRiskRules, "comma-separated list of risk rules (by their ID) to skip")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.ignoreOrphanedRiskTrackingFlag, ignoreOrphanedRiskTrackingFlagName, defaultConfig.IgnoreOrphanedRiskTracking, "ignore orphaned risk tracking (just log them) not matching a concrete risk")
	what.rootCmd.PersistentFlags().StringVar(&what.flags.templateFileNameFlag, templateFileNameFlagName, defaultConfig.TemplateFilename, "background pdf file")

	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateDataFlowDiagramFlag, generateDataFlowDiagramFlagName, true, "generate data flow diagram")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateDataAssetDiagramFlag, generateDataAssetDiagramFlagName, true, "generate data asset diagram")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateRisksJSONFlag, generateRisksJSONFlagName, true, "generate risks json")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateTechnicalAssetsJSONFlag, generateTechnicalAssetsJSONFlagName, true, "generate technical assets json")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateStatsJSONFlag, generateStatsJSONFlagName, true, "generate stats json")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateRisksExcelFlag, generateRisksExcelFlagName, true, "generate risks excel")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateTagsExcelFlag, generateTagsExcelFlagName, true, "generate tags excel")
	what.rootCmd.PersistentFlags().BoolVar(&what.flags.generateReportPDFFlag, generateReportPDFFlagName, true, "generate report pdf, including diagrams")

	return what
}

func (what *Threagile) run(cmd *cobra.Command, _ []string) {
	if !what.flags.interactiveFlag {
		cmd.Println("Please add the --interactive flag to run in interactive mode.")
		return
	}

	completer := readline.NewPrefixCompleter()
	for _, child := range what.rootCmd.Commands() {
		what.cobraToReadline(completer, child)
	}

	dir, homeError := os.UserHomeDir()
	if homeError != nil {
		cmd.Println("Error, please report bug at https://github.com/Threagile/threagile. Unable to find home directory: " + homeError.Error())
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
		cmd.Println("Error, please report bug at https://github.com/Threagile/threagile. Unable to initialize readline: " + readlineError.Error())
		return
	}

	defer func() { _ = shell.Close() }()

	for {
		line, readError := shell.Readline()
		if readError == readline.ErrInterrupt {
			return
		}
		if readError != nil {
			cmd.Println("Error, please report bug at https://github.com/Threagile/threagile. Unable to read line: " + readError.Error())
			return
		}

		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		params, parseError := shellwords.Parse(line)
		if parseError != nil {
			cmd.Printf("failed to parse command line: %s", parseError.Error())
			continue
		}

		cmd, args, findError := what.rootCmd.Find(params)
		if findError != nil {
			cmd.Printf("failed to find command: %s", findError.Error())
			continue
		}

		if cmd == nil || cmd == what.rootCmd {
			cmd.Println("failed to find command")
			continue
		}

		flagsError := cmd.ParseFlags(args)
		if flagsError != nil {
			cmd.Printf("invalid flags: %s", flagsError.Error())
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
				cmd.Printf("error: %v \n", runError)
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
		cmd.Printf("WARNING: failed to load config file %q: %v\n", what.flags.configFlag, configError)
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
	if isFlagOverridden(flags, pluginDirFlagName) {
		cfg.PluginFolder = cfg.CleanPath(what.flags.pluginDirFlag)
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
