package threagile

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/report"
)

func DoIt(config *common.Config, commands *report.GenerateCommands) {
	progressReporter := common.DefaultProgressReporter{Verbose: config.Verbose}
	defer func() {
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			progressReporter.Info("ERROR: " + err.Error())
			_, _ = os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(2)
		}
	}()

	r, err := model.ReadAndAnalyzeModel(*config, progressReporter)
	if err != nil {
		log.Fatal(err)
		return
	}

	if len(config.ExecuteModelMacro) > 0 {
		err := macros.ExecuteModelMacro(r.ModelInput, config.InputFile, r.ParsedModel, config.ExecuteModelMacro)
		if err != nil {
			log.Fatal("Unable to execute model macro: ", err)
		}
		return
	}

	err = report.Generate(config, r, commands, progressReporter)
	if err != nil {
		log.Fatal(err)
		return
	}
}

// TODO: remove from here as soon as moved to cobra, here is only for a backward compatibility
// this file supposed to be only about the logic
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

func ParseCommandlineArgs(buildTimestamp string) (common.Config, report.GenerateCommands) {
	configFile := flag.String("config", "", "config file")
	config := new(common.Config).Defaults(buildTimestamp)
	configError := config.Load(*configFile)
	if configError != nil {
		fmt.Printf("WARNING: failed to load config file %q: %v\n", *configFile, configError)
	}

	// folders
	flag.StringVar(&config.AppFolder, "app-dir", common.AppDir, "app folder (default: "+common.AppDir+")")
	flag.StringVar(&config.ServerFolder, "server-dir", common.DataDir, "base folder for server mode (default: "+common.DataDir+")")
	flag.StringVar(&config.TempFolder, "temp-dir", common.TempDir, "temporary folder location")
	flag.StringVar(&config.BinFolder, "bin-dir", common.BinDir, "binary folder location")
	flag.StringVar(&config.OutputFolder, "output", ".", "output directory")

	// files
	flag.StringVar(&config.InputFile, "model", common.InputFile, "input model yaml file")
	flag.StringVar(&config.RAAPlugin, "raa-run", "raa_calc", "RAA calculation run file name")

	// flags / parameters
	flag.BoolVar(&config.Verbose, "verbose", false, "verbose output")
	flag.IntVar(&config.DiagramDPI, "diagram-dpi", config.DiagramDPI, "DPI used to render: maximum is "+strconv.Itoa(config.MaxGraphvizDPI)+"")
	flag.StringVar(&config.SkipRiskRules, "skip-risk-rules", "", "comma-separated list of risk rules (by their ID) to skip")
	flag.BoolVar(&config.IgnoreOrphanedRiskTracking, "ignore-orphaned-risk-tracking", false, "ignore orphaned risk tracking (just log them) not matching a concrete risk")
	flag.IntVar(&config.ServerPort, "server", 0, "start a server (instead of commandline execution) on the given port")
	flag.StringVar(&config.ExecuteModelMacro, "execute-model-macro", "", "Execute model macro (by ID)")
	flag.StringVar(&config.TemplateFilename, "background", "background.pdf", "background pdf file")
	riskRulesPlugins := flag.String("custom-risk-rules-plugins", "", "comma-separated list of plugins file names with custom risk rules to load")
	config.RiskRulesPlugins = strings.Split(*riskRulesPlugins, ",")

	// commands
	commands := new(report.GenerateCommands).Defaults()
	flag.BoolVar(&commands.DataFlowDiagram, "generate-data-flow-diagram", true, "generate data-flow diagram")
	flag.BoolVar(&commands.DataAssetDiagram, "generate-data-asset-diagram", true, "generate data asset diagram")
	flag.BoolVar(&commands.RisksJSON, "generate-risks-json", true, "generate risks json")
	flag.BoolVar(&commands.StatsJSON, "generate-stats-json", true, "generate stats json")
	flag.BoolVar(&commands.TechnicalAssetsJSON, "generate-technical-assets-json", true, "generate technical assets json")
	flag.BoolVar(&commands.RisksExcel, "generate-risks-excel", true, "generate risks excel")
	flag.BoolVar(&commands.TagsExcel, "generate-tags-excel", true, "generate tags excel")
	flag.BoolVar(&commands.ReportPDF, "generate-report-pdf", true, "generate report pdf, including diagrams")

	flag.Usage = func() {
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
		_, _ = fmt.Fprintf(os.Stderr, "Usage: threagile [options]")
		fmt.Println()
	}
	flag.Parse()

	config.InputFile = expandPath(config.InputFile)
	config.AppFolder = expandPath(config.AppFolder)
	config.ServerFolder = expandPath(config.ServerFolder)
	config.TempFolder = expandPath(config.TempFolder)
	config.BinFolder = expandPath(config.BinFolder)
	config.OutputFolder = expandPath(config.OutputFolder)

	return *config, *commands
}
