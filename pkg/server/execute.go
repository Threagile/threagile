/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func (s *server) analyze(ginContext *gin.Context) {
	s.execute(ginContext, false)
}

func (s *server) check(ginContext *gin.Context) {
	_, ok := s.execute(ginContext, true)
	if ok {
		ginContext.JSON(http.StatusOK, gin.H{
			"message": "model is ok",
		})
	}
}

func (s *server) execute(ginContext *gin.Context, dryRun bool) (yamlContent []byte, ok bool) {
	defer func() {
		var err error
		if r := recover(); r != nil {
			s.errorCount++
			err = r.(error)
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()

	dpi, err := strconv.Atoi(ginContext.DefaultQuery("dpi", strconv.Itoa(s.config.GraphvizDPI)))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}

	fileUploaded, header, err := ginContext.Request.FormFile("file")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}

	if header.Size > 50000000 {
		msg := "maximum model upload file size exceeded (denial-of-service protection)"
		log.Println(msg)
		ginContext.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": msg,
		})
		return yamlContent, false
	}

	filenameUploaded := strings.TrimSpace(header.Filename)

	tmpInputDir, err := os.MkdirTemp(s.config.TempFolder, "threagile-input-")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}
	defer func() { _ = os.RemoveAll(tmpInputDir) }()

	tmpModelFile, err := os.CreateTemp(tmpInputDir, "threagile-model-*")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}
	defer func() { _ = os.Remove(tmpModelFile.Name()) }()
	_, err = io.Copy(tmpModelFile, fileUploaded)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}

	yamlFile := tmpModelFile.Name()

	if strings.ToLower(filepath.Ext(filenameUploaded)) == ".zip" {
		// unzip first (including the resources like images etc.)
		if s.config.Verbose {
			fmt.Println("Decompressing uploaded archive")
		}
		filenamesUnzipped, err := unzip(tmpModelFile.Name(), tmpInputDir)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return yamlContent, false
		}
		found := false
		for _, name := range filenamesUnzipped {
			if strings.ToLower(filepath.Ext(name)) == ".yaml" {
				yamlFile = name
				found = true
				break
			}
		}
		if !found {
			panic(fmt.Errorf("no yaml file found in uploaded archive"))
		}
	}

	tmpOutputDir, err := os.MkdirTemp(s.config.TempFolder, "threagile-output-")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()

	tmpResultFile, err := os.CreateTemp(s.config.TempFolder, "threagile-result-*.zip")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}
	defer func() { _ = os.Remove(tmpResultFile.Name()) }()

	if dryRun {
		s.doItViaRuntimeCall(yamlFile, tmpOutputDir, false, false, false, false, false, true, true, true, 40)
	} else {
		s.doItViaRuntimeCall(yamlFile, tmpOutputDir, true, true, true, true, true, true, true, true, dpi)
	}

	yamlContent, err = os.ReadFile(filepath.Clean(yamlFile))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}
	err = os.WriteFile(filepath.Join(tmpOutputDir, s.config.InputFile), yamlContent, 0400)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}

	if !dryRun {
		files := []string{
			filepath.Join(tmpOutputDir, s.config.InputFile),
			filepath.Join(tmpOutputDir, s.config.DataFlowDiagramFilenamePNG),
			filepath.Join(tmpOutputDir, s.config.DataAssetDiagramFilenamePNG),
			filepath.Join(tmpOutputDir, s.config.ReportFilename),
			filepath.Join(tmpOutputDir, s.config.ExcelRisksFilename),
			filepath.Join(tmpOutputDir, s.config.ExcelTagsFilename),
			filepath.Join(tmpOutputDir, s.config.JsonRisksFilename),
			filepath.Join(tmpOutputDir, s.config.JsonTechnicalAssetsFilename),
			filepath.Join(tmpOutputDir, s.config.JsonStatsFilename),
		}
		if s.config.KeepDiagramSourceFiles {
			files = append(files, filepath.Join(tmpOutputDir, s.config.DataAssetDiagramFilenamePNG))
			files = append(files, filepath.Join(tmpOutputDir, s.config.DataAssetDiagramFilenameDOT))
		}
		err = zipFiles(tmpResultFile.Name(), files)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return yamlContent, false
		}
		if s.config.Verbose {
			log.Println("Streaming back result file: " + tmpResultFile.Name())
		}
		ginContext.FileAttachment(tmpResultFile.Name(), "threagile-result.zip")
	}
	s.successCount++
	return yamlContent, true
}

// ultimately to avoid any in-process memory and/or data leaks by the used third party libs like PDF generation: exec and quit
func (s *server) doItViaRuntimeCall(modelFile string, outputDir string,
	generateDataFlowDiagram, generateDataAssetDiagram, generateReportPdf, generateRisksExcel, generateTagsExcel, generateRisksJSON, generateTechnicalAssetsJSON, generateStatsJSON bool,
	dpi int) {
	// Remember to also add the same args to the exec based sub-process calls!
	var cmd *exec.Cmd
	args := []string{"-model", modelFile, "-output", outputDir, "-execute-model-macro", s.config.ExecuteModelMacro, "-raa-run", s.config.RAAPlugin, "-custom-risk-rules-plugins", strings.Join(s.config.RiskRulesPlugins, ","), "-skip-risk-rules", s.config.SkipRiskRules, "-diagram-dpi", strconv.Itoa(dpi)}
	if s.config.Verbose {
		args = append(args, "-verbose")
	}
	if s.config.IgnoreOrphanedRiskTracking { // TODO why add all them as arguments, when they are also variables on outer level?
		args = append(args, "-ignore-orphaned-risk-tracking")
	}
	if generateDataFlowDiagram {
		args = append(args, "-generate-data-flow-diagram")
	}
	if generateDataAssetDiagram {
		args = append(args, "-generate-data-asset-diagram")
	}
	if generateReportPdf {
		args = append(args, "-generate-report-pdf")
	}
	if generateRisksExcel {
		args = append(args, "-generate-risks-excel")
	}
	if generateTagsExcel {
		args = append(args, "-generate-tags-excel")
	}
	if generateRisksJSON {
		args = append(args, "-generate-risks-json")
	}
	if generateTechnicalAssetsJSON {
		args = append(args, "-generate-technical-assets-json")
	}
	if generateStatsJSON {
		args = append(args, "-generate-stats-json")
	}
	self, nameError := os.Executable()
	if nameError != nil {
		panic(nameError)
	}

	cmd = exec.Command(self, args...) // #nosec G204
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic(fmt.Errorf(string(out)))
	} else {
		if s.config.Verbose && len(out) > 0 {
			fmt.Println("---")
			fmt.Print(string(out))
			fmt.Println("---")
		}
	}
}
