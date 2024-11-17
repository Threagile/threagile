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

	dpi, err := strconv.Atoi(ginContext.DefaultQuery("dpi", strconv.Itoa(s.config.GetGraphvizDPI())))
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

	tmpInputDir, err := os.MkdirTemp(s.config.GetTempFolder(), "threagile-input-")
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
		if s.config.GetVerbose() {
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

	tmpOutputDir, err := os.MkdirTemp(s.config.GetTempFolder(), "threagile-output-")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()

	tmpResultFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-result-*.zip")
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
	err = os.WriteFile(filepath.Join(tmpOutputDir, s.config.GetInputFile()), yamlContent, 0400)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}

	if !dryRun {
		files := []string{
			filepath.Join(tmpOutputDir, s.config.GetInputFile()),
			filepath.Join(tmpOutputDir, s.config.GetDataFlowDiagramFilenamePNG()),
			filepath.Join(tmpOutputDir, s.config.GetDataAssetDiagramFilenamePNG()),
			filepath.Join(tmpOutputDir, s.config.GetReportFilename()),
			filepath.Join(tmpOutputDir, s.config.GetExcelRisksFilename()),
			filepath.Join(tmpOutputDir, s.config.GetExcelTagsFilename()),
			filepath.Join(tmpOutputDir, s.config.GetJsonRisksFilename()),
			filepath.Join(tmpOutputDir, s.config.GetJsonTechnicalAssetsFilename()),
			filepath.Join(tmpOutputDir, s.config.GetJsonStatsFilename()),
		}
		if s.config.GetKeepDiagramSourceFiles() {
			files = append(files, filepath.Join(tmpOutputDir, s.config.GetDataAssetDiagramFilenamePNG()))
			files = append(files, filepath.Join(tmpOutputDir, s.config.GetDataAssetDiagramFilenameDOT()))
		}
		err = zipFiles(tmpResultFile.Name(), files)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return yamlContent, false
		}
		if s.config.GetVerbose() {
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
	args := []string{"-model", modelFile, "-output", outputDir, "-execute-model-macro", s.config.GetExecuteModelMacro(), "-custom-risk-rules-plugins", strings.Join(s.config.GetRiskRulePlugins(), ","), "-skip-risk-rules", strings.Join(s.config.GetSkipRiskRules(), ","), "-diagram-dpi", strconv.Itoa(dpi)}
	if s.config.GetVerbose() {
		args = append(args, "-verbose")
	}
	if s.config.GetIgnoreOrphanedRiskTracking() { // TODO why add all them as arguments, when they are also variables on outer level?
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
		panic(fmt.Errorf("%v", string(out)))
	} else {
		if s.config.GetVerbose() && len(out) > 0 {
			fmt.Println("---")
			fmt.Print(string(out))
			fmt.Println("---")
		}
	}
}
