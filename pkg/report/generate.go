package report

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/types"
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
	ReportADOC          bool
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
		ReportADOC:          true,
	}
	return c
}

func Generate(config configReader, readResult *model.ReadResult, commands *GenerateCommands, riskRules types.RiskRules) error {
	outputDirError := os.MkdirAll(config.GetOutputFolder(), 0700)
	if outputDirError != nil {
		return fmt.Errorf("failed to create output dir %q: %w", config.GetOutputFolder(), outputDirError)
	}

	tempDirError := os.MkdirAll(config.GetTempFolder(), 0700)
	if tempDirError != nil {
		return fmt.Errorf("failed to create temp dir %q: %w", config.GetTempFolder(), tempDirError)
	}

	generateDataFlowDiagram := commands.DataFlowDiagram
	generateDataAssetsDiagram := commands.DataAssetDiagram

	if commands.ReportPDF || commands.ReportADOC { // as the PDF report includes both diagrams
		if !generateDataFlowDiagram {
			dataFlowFile := filepath.Join(config.GetOutputFolder(), config.GetDataFlowDiagramFilenamePNG())
			if _, err := os.Stat(dataFlowFile); errors.Is(err, os.ErrNotExist) {
				config.GetProgressReporter().Warnf("Forcibly create the needed Data-Flow Diagram file to enable report generation.")
				generateDataFlowDiagram = true
			}
		}
		if !generateDataAssetsDiagram {
			dataAssetFile := filepath.Join(config.GetOutputFolder(), config.GetDataAssetDiagramFilenamePNG())
			if _, err := os.Stat(dataAssetFile); errors.Is(err, os.ErrNotExist) {
				config.GetProgressReporter().Warnf("Forcibly create the needed Data-Asset Diagram file to enable report generation.")
				generateDataAssetsDiagram = true
			}
		}
	}

	diagramDPI := config.GetDiagramDPI()
	if diagramDPI < config.GetMinGraphvizDPI() {
		diagramDPI = config.GetMinGraphvizDPI()
	} else if diagramDPI > config.GetMaxGraphvizDPI() {
		diagramDPI = config.GetMaxGraphvizDPI()
	}
	// Data-flow Diagram rendering
	if generateDataFlowDiagram {
		gvFile := filepath.Join(config.GetOutputFolder(), config.GetDataFlowDiagramFilenameDOT())
		if !config.GetKeepDiagramSourceFiles() {
			tmpFileGV, err := os.CreateTemp(config.GetTempFolder(), config.GetDataFlowDiagramFilenameDOT())
			if err != nil {
				return err
			}
			gvFile = tmpFileGV.Name()
			defer func() { _ = os.Remove(gvFile) }()
		}
		dotFile, err := WriteDataFlowDiagramGraphvizDOT(readResult.ParsedModel, gvFile, diagramDPI, config.GetAddModelTitle(), config.GetAddLegend(), config.GetProgressReporter())
		if err != nil {
			return fmt.Errorf("error while generating data flow diagram: %w", err)
		}

		err = GenerateDataFlowDiagramGraphvizImage(dotFile, config.GetOutputFolder(),
			config.GetTempFolder(), config.GetDataFlowDiagramFilenamePNG(), config.GetProgressReporter(), config.GetKeepDiagramSourceFiles())
		if err != nil {
			config.GetProgressReporter().Warn(err)
		}
	}
	// Data Asset Diagram rendering
	if generateDataAssetsDiagram {
		gvFile := filepath.Join(config.GetOutputFolder(), config.GetDataAssetDiagramFilenameDOT())
		if !config.GetKeepDiagramSourceFiles() {
			tmpFile, err := os.CreateTemp(config.GetTempFolder(), config.GetDataAssetDiagramFilenameDOT())
			if err != nil {
				return err
			}
			gvFile = tmpFile.Name()
			defer func() { _ = os.Remove(gvFile) }()
		}
		dotFile, err := WriteDataAssetDiagramGraphvizDOT(readResult.ParsedModel, gvFile, diagramDPI, config.GetProgressReporter())
		if err != nil {
			return fmt.Errorf("error while generating data asset diagram: %w", err)
		}
		err = GenerateDataAssetDiagramGraphvizImage(dotFile, config.GetOutputFolder(),
			config.GetTempFolder(), config.GetDataAssetDiagramFilenamePNG(), config.GetProgressReporter())
		if err != nil {
			config.GetProgressReporter().Warn(err)
		}
	}

	// risks as risks json
	if commands.RisksJSON {
		config.GetProgressReporter().Info("Writing risks json")
		err := WriteRisksJSON(readResult.ParsedModel, filepath.Join(config.GetOutputFolder(), config.GetJsonRisksFilename()))
		if err != nil {
			return fmt.Errorf("error while writing risks json: %w", err)
		}
	}

	// technical assets json
	if commands.TechnicalAssetsJSON {
		config.GetProgressReporter().Info("Writing technical assets json")
		err := WriteTechnicalAssetsJSON(readResult.ParsedModel, filepath.Join(config.GetOutputFolder(), config.GetJsonTechnicalAssetsFilename()))
		if err != nil {
			return fmt.Errorf("error while writing technical assets json: %w", err)
		}
	}

	// risks as risks json
	if commands.StatsJSON {
		config.GetProgressReporter().Info("Writing stats json")
		err := WriteStatsJSON(readResult.ParsedModel, filepath.Join(config.GetOutputFolder(), config.GetJsonStatsFilename()))
		if err != nil {
			return fmt.Errorf("error while writing stats json: %w", err)
		}
	}

	// risks Excel
	if commands.RisksExcel {
		config.GetProgressReporter().Info("Writing risks excel")
		err := WriteRisksExcelToFile(readResult.ParsedModel, filepath.Join(config.GetOutputFolder(), config.GetExcelRisksFilename()), config)
		if err != nil {
			return err
		}
	}

	// tags Excel
	if commands.TagsExcel {
		config.GetProgressReporter().Info("Writing tags excel")
		err := WriteTagsExcelToFile(readResult.ParsedModel, filepath.Join(config.GetOutputFolder(), config.GetExcelTagsFilename()), config)
		if err != nil {
			return err
		}
	}

	if commands.ReportPDF {
		// hash the YAML input file
		f, err := os.Open(config.GetInputFile())
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
		config.GetProgressReporter().Info("Writing report pdf")

		pdfReporter := newPdfReporter(riskRules)
		err = pdfReporter.WriteReportPDF(filepath.Join(config.GetOutputFolder(), config.GetReportFilename()),
			filepath.Join(config.GetAppFolder(), config.GetTemplateFilename()),
			filepath.Join(config.GetOutputFolder(), config.GetDataFlowDiagramFilenamePNG()),
			filepath.Join(config.GetOutputFolder(), config.GetDataAssetDiagramFilenamePNG()),
			config.GetInputFile(),
			config.GetSkipRiskRules(),
			config.GetBuildTimestamp(),
			config.GetThreagileVersion(),
			modelHash,
			readResult.IntroTextRAA,
			readResult.CustomRiskRules,
			config.GetTempFolder(),
			readResult.ParsedModel,
			config.GetReportConfigurationHideChapters())
		if err != nil {
			return err
		}
	}

	if commands.ReportADOC {
		// hash the YAML input file
		f, err := os.Open(config.GetInputFile())
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		hasher := sha256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			return err
		}

		modelHash := hex.EncodeToString(hasher.Sum(nil))
		// report ADOC
		config.GetProgressReporter().Info("Writing report adoc")
		adocReporter := NewAdocReport(config.GetOutputFolder(), riskRules)
		err = adocReporter.WriteReport(readResult.ParsedModel,
			filepath.Join(config.GetOutputFolder(), config.GetDataFlowDiagramFilenamePNG()),
			filepath.Join(config.GetOutputFolder(), config.GetDataAssetDiagramFilenamePNG()),
			config.GetInputFile(),
			config.GetSkipRiskRules(),
			config.GetBuildTimestamp(),
			config.GetThreagileVersion(),
			modelHash,
			readResult.IntroTextRAA,
			readResult.CustomRiskRules,
			config.GetReportLogoImagePath(),
			config.GetReportConfigurationHideChapters())
		if err != nil {
			return err
		}
	}

	return nil
}

type progressReporter interface {
	Info(a ...any)
	Warn(a ...any)
	Error(a ...any)
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}
