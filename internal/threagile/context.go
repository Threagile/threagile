package threagile

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt" // TODO: no fmt.Println here
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/run"
	"github.com/threagile/threagile/pkg/security/risks"
	"github.com/threagile/threagile/pkg/security/types"
)

type GenerateCommands struct {
	DataFlowDiagram     bool
	DataAssetDiagram    bool
	RisksJSON           bool
	TechnicalAssetsJSON bool
	StatsJSON           bool
	RisksExcel          bool
	TagsExcel           bool
	ReportPDF           bool
}

func (c *GenerateCommands) Defaults() *GenerateCommands {
	*c = GenerateCommands{
		DataFlowDiagram:     true,
		DataAssetDiagram:    true,
		RisksJSON:           true,
		TechnicalAssetsJSON: true,
		StatsJSON:           true,
		RisksExcel:          true,
		TagsExcel:           true,
		ReportPDF:           true,
	}
	return c
}

func DoIt(config *common.Config, commands *GenerateCommands) {
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

	if len(config.ExecuteModelMacro) > 0 {
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
	}
	progressReporter.Info("Writing into output directory:", config.OutputFolder)
	progressReporter.Info("Parsing model:", config.InputFile)

	builtinRiskRules := make(map[string]types.RiskRule)
	for _, rule := range risks.GetBuiltInRiskRules() {
		builtinRiskRules[rule.Category().Id] = rule
	}
	customRiskRules := types.LoadCustomRiskRules(config.RiskRulesPlugins, progressReporter)

	modelInput := *new(input.ModelInput).Defaults()
	loadError := modelInput.Load(config.InputFile)
	if loadError != nil {
		log.Fatal("Unable to load model yaml: ", loadError)
	}

	parsedModel, parseError := model.ParseModel(&modelInput, builtinRiskRules, customRiskRules)
	if parseError != nil {
		log.Fatal("Unable to parse model yaml: ", parseError)
	}
	introTextRAA := applyRAA(parsedModel, config.BinFolder, config.RAAPlugin, progressReporter)

	parsedModel.ApplyRiskGeneration(customRiskRules, builtinRiskRules,
		config.SkipRiskRules, progressReporter)
	err := parsedModel.ApplyWildcardRiskTrackingEvaluation(config.IgnoreOrphanedRiskTracking, progressReporter)
	if err != nil {
		// TODO: do not panic and gracefully handle the error
		panic(err)
	}

	err = parsedModel.CheckRiskTracking(config.IgnoreOrphanedRiskTracking, progressReporter)
	if err != nil {
		// TODO: do not panic and gracefully handle the error
		panic(err)
	}

	if len(config.ExecuteModelMacro) > 0 {
		err := macros.ExecuteModelMacro(&modelInput, config.InputFile, parsedModel, config.ExecuteModelMacro)
		if err != nil {
			log.Fatal("Unable to execute model macro: ", err)
		}
		return
	}

	generateDataFlowDiagram := commands.DataFlowDiagram
	generateDataAssetsDiagram := commands.DataAssetDiagram
	if commands.ReportPDF { // as the PDF report includes both diagrams
		generateDataFlowDiagram = true
		generateDataAssetsDiagram = true
	}

	diagramDPI := config.DiagramDPI
	if diagramDPI < common.MinGraphvizDPI {
		diagramDPI = common.MinGraphvizDPI
	} else if diagramDPI > common.MaxGraphvizDPI {
		diagramDPI = common.MaxGraphvizDPI
	}
	// Data-flow Diagram rendering
	if generateDataFlowDiagram {
		gvFile := filepath.Join(config.OutputFolder, config.DataFlowDiagramFilenameDOT)
		if !config.KeepDiagramSourceFiles {
			tmpFileGV, err := os.CreateTemp(config.TempFolder, config.DataFlowDiagramFilenameDOT)
			checkErr(err)
			gvFile = tmpFileGV.Name()
			defer func() { _ = os.Remove(gvFile) }()
		}
		dotFile := report.WriteDataFlowDiagramGraphvizDOT(parsedModel, gvFile, diagramDPI, config.AddModelTitle, progressReporter)

		err := report.GenerateDataFlowDiagramGraphvizImage(dotFile, config.OutputFolder,
			config.TempFolder, config.BinFolder, config.DataFlowDiagramFilenamePNG, progressReporter)
		if err != nil {
			fmt.Println(err)
		}
	}
	// Data Asset Diagram rendering
	if generateDataAssetsDiagram {
		gvFile := filepath.Join(config.OutputFolder, config.DataAssetDiagramFilenameDOT)
		if !config.KeepDiagramSourceFiles {
			tmpFile, err := os.CreateTemp(config.TempFolder, config.DataAssetDiagramFilenameDOT)
			checkErr(err)
			gvFile = tmpFile.Name()
			defer func() { _ = os.Remove(gvFile) }()
		}
		dotFile := report.WriteDataAssetDiagramGraphvizDOT(parsedModel, gvFile, diagramDPI, progressReporter)
		err := report.GenerateDataAssetDiagramGraphvizImage(dotFile, config.OutputFolder,
			config.TempFolder, config.BinFolder, config.DataAssetDiagramFilenamePNG, progressReporter)
		if err != nil {
			fmt.Println(err)
		}
	}

	// risks as risks json
	if commands.RisksJSON {
		progressReporter.Info("Writing risks json")
		report.WriteRisksJSON(parsedModel, filepath.Join(config.OutputFolder, config.JsonRisksFilename))
	}

	// technical assets json
	if commands.TechnicalAssetsJSON {
		progressReporter.Info("Writing technical assets json")
		report.WriteTechnicalAssetsJSON(parsedModel, filepath.Join(config.OutputFolder, config.JsonTechnicalAssetsFilename))
	}

	// risks as risks json
	if commands.StatsJSON {
		progressReporter.Info("Writing stats json")
		report.WriteStatsJSON(parsedModel, filepath.Join(config.OutputFolder, config.JsonStatsFilename))
	}

	// risks Excel
	if commands.RisksExcel {
		progressReporter.Info("Writing risks excel")
		report.WriteRisksExcelToFile(parsedModel, filepath.Join(config.OutputFolder, config.ExcelRisksFilename))
	}

	// tags Excel
	if commands.TagsExcel {
		progressReporter.Info("Writing tags excel")
		report.WriteTagsExcelToFile(parsedModel, filepath.Join(config.OutputFolder, config.ExcelTagsFilename))
	}

	if commands.ReportPDF {
		// hash the YAML input file
		f, err := os.Open(config.InputFile)
		checkErr(err)
		defer func() { _ = f.Close() }()
		hasher := sha256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			panic(err)
		}
		modelHash := hex.EncodeToString(hasher.Sum(nil))
		// report PDF
		progressReporter.Info("Writing report pdf")
		report.WriteReportPDF(filepath.Join(config.OutputFolder, config.ReportFilename),
			filepath.Join(config.AppFolder, config.TemplateFilename),
			filepath.Join(config.OutputFolder, config.DataFlowDiagramFilenamePNG),
			filepath.Join(config.OutputFolder, config.DataAssetDiagramFilenamePNG),
			config.InputFile,
			config.SkipRiskRules,
			config.BuildTimestamp,
			modelHash,
			introTextRAA,
			customRiskRules,
			config.TempFolder,
			parsedModel)
	}
}

func applyRAA(parsedModel *types.ParsedModel, binFolder, raaPlugin string, progressReporter common.DefaultProgressReporter) string {
	progressReporter.Info("Applying RAA calculation:", raaPlugin)

	runner, loadError := new(run.Runner).Load(filepath.Join(binFolder, raaPlugin))
	if loadError != nil {
		progressReporter.Warn(fmt.Sprintf("WARNING: raa %q not loaded: %v\n", raaPlugin, loadError))
		return ""
	}

	runError := runner.Run(parsedModel, parsedModel)
	if runError != nil {
		progressReporter.Warn(fmt.Sprintf("WARNING: raa %q not applied: %v\n", raaPlugin, runError))
		return ""
	}

	return runner.ErrorOutput
}

func checkErr(err error) {
	if err != nil {
		panic(err)
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

func ParseCommandlineArgs(buildTimestamp string) (common.Config, GenerateCommands) {
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
	commands := new(GenerateCommands).Defaults()
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
