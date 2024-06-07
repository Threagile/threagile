/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type responseType int

const (
	dataFlowDiagram responseType = iota
	dataAssetDiagram
	reportPDF
	risksExcel
	tagsExcel
	risksJSON
	technicalAssetsJSON
	statsJSON
)

func (s *server) streamDataFlowDiagram(ginContext *gin.Context) {
	s.streamResponse(ginContext, dataFlowDiagram)
}

func (s *server) streamDataAssetDiagram(ginContext *gin.Context) {
	s.streamResponse(ginContext, dataAssetDiagram)
}

func (s *server) streamReportPDF(ginContext *gin.Context) {
	s.streamResponse(ginContext, reportPDF)
}

func (s *server) streamRisksExcel(ginContext *gin.Context) {
	s.streamResponse(ginContext, risksExcel)
}

func (s *server) streamTagsExcel(ginContext *gin.Context) {
	s.streamResponse(ginContext, tagsExcel)
}

func (s *server) streamRisksJSON(ginContext *gin.Context) {
	s.streamResponse(ginContext, risksJSON)
}

func (s *server) streamTechnicalAssetsJSON(ginContext *gin.Context) {
	s.streamResponse(ginContext, technicalAssetsJSON)
}

func (s *server) streamStatsJSON(ginContext *gin.Context) {
	s.streamResponse(ginContext, statsJSON)
}

func (s *server) streamResponse(ginContext *gin.Context, responseType responseType) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer func() {
		s.unlockFolder(folderNameOfKey)
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if s.config.Verbose() {
				log.Println(err)
			}
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()
	dpi, err := strconv.Atoi(ginContext.DefaultQuery("dpi", strconv.Itoa(s.config.GraphvizDPI())))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	_, yamlText, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if !ok {
		return
	}
	tmpModelFile, err := os.CreateTemp(s.config.TempFolder(), "threagile-render-*")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.Remove(tmpModelFile.Name()) }()
	tmpOutputDir, err := os.MkdirTemp(s.config.TempFolder(), "threagile-render-")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()
	err = os.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400)
	if responseType == dataFlowDiagram {
		s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, true, false, false, false, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.File(filepath.Clean(filepath.Join(tmpOutputDir, s.config.DataFlowDiagramFilenamePNG())))
	} else if responseType == dataAssetDiagram {
		s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, true, false, false, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.File(filepath.Clean(filepath.Join(tmpOutputDir, s.config.DataAssetDiagramFilenamePNG())))
	} else if responseType == reportPDF {
		s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, true, false, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.FileAttachment(filepath.Clean(filepath.Join(tmpOutputDir, s.config.ReportFilename())), s.config.ReportFilename())
	} else if responseType == risksExcel {
		s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, true, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.FileAttachment(filepath.Clean(filepath.Join(tmpOutputDir, s.config.ExcelRisksFilename())), s.config.ExcelRisksFilename())
	} else if responseType == tagsExcel {
		s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, false, true, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.FileAttachment(filepath.Clean(filepath.Join(tmpOutputDir, s.config.ExcelTagsFilename())), s.config.ExcelTagsFilename())
	} else if responseType == risksJSON {
		s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, false, false, true, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		jsonData, err := os.ReadFile(filepath.Clean(filepath.Join(tmpOutputDir, s.config.JsonRisksFilename())))
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.Data(http.StatusOK, "application/json", jsonData) // stream directly with JSON content-type in response instead of file download
	} else if responseType == technicalAssetsJSON {
		s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, false, false, true, true, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		jsonData, err := os.ReadFile(filepath.Clean(filepath.Join(tmpOutputDir, s.config.JsonTechnicalAssetsFilename())))
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.Data(http.StatusOK, "application/json", jsonData) // stream directly with JSON content-type in response instead of file download
	} else if responseType == statsJSON {
		s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, false, false, false, false, true, dpi)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		jsonData, err := os.ReadFile(filepath.Clean(filepath.Join(tmpOutputDir, s.config.JsonStatsFilename())))
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.Data(http.StatusOK, "application/json", jsonData) // stream directly with JSON content-type in response instead of file download
	}
}
