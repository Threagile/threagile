package report

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/model"
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

func Generate(config *common.Config, readResult *model.ReadResult, commands *GenerateCommands, progressReporter progressReporter) error {
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
			if err != nil {
				return err
			}
			gvFile = tmpFileGV.Name()
			defer func() { _ = os.Remove(gvFile) }()
		}
		dotFile := WriteDataFlowDiagramGraphvizDOT(readResult.ParsedModel, gvFile, diagramDPI, config.AddModelTitle, progressReporter)

		err := GenerateDataFlowDiagramGraphvizImage(dotFile, config.OutputFolder,
			config.TempFolder, config.BinFolder, config.DataFlowDiagramFilenamePNG, progressReporter)
		if err != nil {
			progressReporter.Warn(err)
		}
	}
	// Data Asset Diagram rendering
	if generateDataAssetsDiagram {
		gvFile := filepath.Join(config.OutputFolder, config.DataAssetDiagramFilenameDOT)
		if !config.KeepDiagramSourceFiles {
			tmpFile, err := os.CreateTemp(config.TempFolder, config.DataAssetDiagramFilenameDOT)
			if err != nil {
				return err
			}
			gvFile = tmpFile.Name()
			defer func() { _ = os.Remove(gvFile) }()
		}
		dotFile := WriteDataAssetDiagramGraphvizDOT(readResult.ParsedModel, gvFile, diagramDPI, progressReporter)
		err := GenerateDataAssetDiagramGraphvizImage(dotFile, config.OutputFolder,
			config.TempFolder, config.BinFolder, config.DataAssetDiagramFilenamePNG, progressReporter)
		if err != nil {
			progressReporter.Warn(err)
		}
	}

	// risks as risks json
	if commands.RisksJSON {
		progressReporter.Info("Writing risks json")
		WriteRisksJSON(readResult.ParsedModel, filepath.Join(config.OutputFolder, config.JsonRisksFilename))
	}

	// technical assets json
	if commands.TechnicalAssetsJSON {
		progressReporter.Info("Writing technical assets json")
		WriteTechnicalAssetsJSON(readResult.ParsedModel, filepath.Join(config.OutputFolder, config.JsonTechnicalAssetsFilename))
	}

	// risks as risks json
	if commands.StatsJSON {
		progressReporter.Info("Writing stats json")
		WriteStatsJSON(readResult.ParsedModel, filepath.Join(config.OutputFolder, config.JsonStatsFilename))
	}

	// risks Excel
	if commands.RisksExcel {
		progressReporter.Info("Writing risks excel")
		WriteRisksExcelToFile(readResult.ParsedModel, filepath.Join(config.OutputFolder, config.ExcelRisksFilename))
	}

	// tags Excel
	if commands.TagsExcel {
		progressReporter.Info("Writing tags excel")
		WriteTagsExcelToFile(readResult.ParsedModel, filepath.Join(config.OutputFolder, config.ExcelTagsFilename))
	}

	if commands.ReportPDF {
		// hash the YAML input file
		f, err := os.Open(config.InputFile)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		hasher := sha256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			return err
		}
		modelHash := hex.EncodeToString(hasher.Sum(nil))
		// report PDF
		progressReporter.Info("Writing report pdf")
		WriteReportPDF(filepath.Join(config.OutputFolder, config.ReportFilename),
			filepath.Join(config.AppFolder, config.TemplateFilename),
			filepath.Join(config.OutputFolder, config.DataFlowDiagramFilenamePNG),
			filepath.Join(config.OutputFolder, config.DataAssetDiagramFilenamePNG),
			config.InputFile,
			config.SkipRiskRules,
			config.BuildTimestamp,
			modelHash,
			readResult.IntroTextRAA,
			readResult.CustomRiskRules,
			config.TempFolder,
			readResult.ParsedModel)
	}

	return nil
}

type progressReporter interface {
	Info(a ...any)
	Warn(a ...any)
	Error(a ...any)
}
