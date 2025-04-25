/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/types"
)

type serverConfigReader interface {
	GetBuildTimestamp() string
	GetVerbose() bool
	GetInteractive() bool
	GetAppFolder() string
	GetPluginFolder() string
	GetDataFolder() string
	GetOutputFolder() string
	GetServerFolder() string
	GetTempFolder() string
	GetKeyFolder() string
	GetInputFile() string
	GetImportedInputFile() string
	GetDataFlowDiagramFilenamePNG() string
	GetDataAssetDiagramFilenamePNG() string
	GetDataFlowDiagramFilenameDOT() string
	GetDataAssetDiagramFilenameDOT() string
	GetReportFilename() string
	GetExcelRisksFilename() string
	GetRiskExcelConfigHideColumns() []string
	GetRiskExcelConfigSortByColumns() []string
	GetRiskExcelConfigWidthOfColumns() map[string]float64
	GetExcelTagsFilename() string
	GetJsonRisksFilename() string
	GetJsonTechnicalAssetsFilename() string
	GetJsonStatsFilename() string
	GetTemplateFilename() string
	GetTechnologyFilename() string
	GetRiskRulePlugins() []string
	GetSkipRiskRules() []string
	GetExecuteModelMacro() string
	GetServerMode() bool
	GetDiagramDPI() int
	GetServerPort() int
	GetGraphvizDPI() int
	GetMaxGraphvizDPI() int
	GetBackupHistoryFilesToKeep() int
	GetAddModelTitle() bool
	GetAddLegend() bool
	GetKeepDiagramSourceFiles() bool
	GetIgnoreOrphanedRiskTracking() bool
	GetThreagileVersion() string
	GetProgressReporter() types.ProgressReporter
}

type server struct {
	config                         serverConfigReader
	successCount                   int
	errorCount                     int
	globalLock                     sync.Mutex
	throttlerLock                  sync.Mutex
	createdObjectsThrottler        map[string][]int64
	mapTokenHashToTimeoutStruct    map[string]timeoutStruct
	mapFolderNameToTokenHash       map[string]string
	extremeShortTimeoutsForTesting bool
	locksByFolderName              map[string]*sync.Mutex
	builtinRiskRules               types.RiskRules
	customRiskRules                types.RiskRules
}

func RunServer(config serverConfigReader, builtinRiskRules types.RiskRules) {
	s := &server{
		config:                         config,
		createdObjectsThrottler:        make(map[string][]int64),
		mapTokenHashToTimeoutStruct:    make(map[string]timeoutStruct),
		mapFolderNameToTokenHash:       make(map[string]string),
		extremeShortTimeoutsForTesting: false,
		locksByFolderName:              make(map[string]*sync.Mutex),
		builtinRiskRules:               builtinRiskRules,
	}
	router := gin.Default()
	router.LoadHTMLGlob(filepath.Join(s.config.GetServerFolder(), "static", "*.html")) // <==
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})
	router.HEAD("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})
	router.GET("/edit-model", func(c *gin.Context) {
		c.HTML(http.StatusOK, "edit-model.html", gin.H{})
	})
	router.HEAD("/edit-model", func(c *gin.Context) {
		c.HTML(http.StatusOK, "edit-model.html", gin.H{})
	})
	router.StaticFile("/css/edit-model.css", filepath.Join(s.config.GetServerFolder(), "static", "css", "edit-model.css"))       // <==
	router.StaticFile("/js/edit-model.js", filepath.Join(s.config.GetServerFolder(), "static", "js", "edit-model.js"))           // <==
	router.StaticFile("/js/property-editor.js", filepath.Join(s.config.GetServerFolder(), "static", "js", "property-editor.js")) // <==
	router.StaticFile("/js/schema.js", filepath.Join(s.config.GetServerFolder(), "static", "js", "schema.js"))                   // <==

	router.StaticFile("/threagile.png", filepath.Join(s.config.GetServerFolder(), "static", "threagile.png")) // <==
	router.StaticFile("/site.webmanifest", filepath.Join(s.config.GetServerFolder(), "static", "site.webmanifest"))
	router.StaticFile("/favicon.ico", filepath.Join(s.config.GetServerFolder(), "static", "favicon.ico"))
	router.StaticFile("/favicon-32x32.png", filepath.Join(s.config.GetServerFolder(), "static", "favicon-32x32.png"))
	router.StaticFile("/favicon-16x16.png", filepath.Join(s.config.GetServerFolder(), "static", "favicon-16x16.png"))
	router.StaticFile("/apple-touch-icon.png", filepath.Join(s.config.GetServerFolder(), "static", "apple-touch-icon.png"))
	router.StaticFile("/android-chrome-512x512.png", filepath.Join(s.config.GetServerFolder(), "static", "android-chrome-512x512.png"))
	router.StaticFile("/android-chrome-192x192.png", filepath.Join(s.config.GetServerFolder(), "static", "android-chrome-192x192.png"))

	router.StaticFile("/schema.json", filepath.Join(s.config.GetAppFolder(), "schema.json"))
	router.StaticFile("/live-templates.txt", filepath.Join(s.config.GetAppFolder(), "live-templates.txt"))
	router.StaticFile("/openapi.yaml", filepath.Join(s.config.GetAppFolder(), "openapi.yaml"))

	router.GET("/threagile-example-model.yaml", s.exampleFile)
	router.GET("/threagile-stub-model.yaml", s.stubFile)

	router.GET("/meta/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	router.GET("/meta/version", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"version":         config.GetThreagileVersion(),
			"build_timestamp": s.config.GetBuildTimestamp(),
		})
	})
	router.GET("/meta/types", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"quantity":                     arrayOfStringValues(types.QuantityValues()),
			"confidentiality":              arrayOfStringValues(types.ConfidentialityValues()),
			"criticality":                  arrayOfStringValues(types.CriticalityValues()),
			"technical_asset_type":         arrayOfStringValues(types.TechnicalAssetTypeValues()),
			"technical_asset_size":         arrayOfStringValues(types.TechnicalAssetSizeValues()),
			"authorization":                arrayOfStringValues(types.AuthorizationValues()),
			"authentication":               arrayOfStringValues(types.AuthenticationValues()),
			"usage":                        arrayOfStringValues(types.UsageValues()),
			"encryption":                   arrayOfStringValues(types.EncryptionStyleValues()),
			"data_format":                  arrayOfStringValues(types.DataFormatValues()),
			"protocol":                     arrayOfStringValues(types.ProtocolValues()),
			"technical_asset_technology":   arrayOfStringValues(types.TechnicalAssetTechnologyValues(config)),
			"technical_asset_machine":      arrayOfStringValues(types.TechnicalAssetMachineValues()),
			"trust_boundary_type":          arrayOfStringValues(types.TrustBoundaryTypeValues()),
			"data_breach_probability":      arrayOfStringValues(types.DataBreachProbabilityValues()),
			"risk_severity":                arrayOfStringValues(types.RiskSeverityValues()),
			"risk_exploitation_likelihood": arrayOfStringValues(types.RiskExploitationLikelihoodValues()),
			"risk_exploitation_impact":     arrayOfStringValues(types.RiskExploitationImpactValues()),
			"risk_function":                arrayOfStringValues(types.RiskFunctionValues()),
			"risk_status":                  arrayOfStringValues(types.RiskStatusValues()),
			"stride":                       arrayOfStringValues(types.STRIDEValues()),
		})
	})

	// TODO router.GET("/meta/risk-rules", listRiskRules)
	// TODO router.GET("/meta/model-macros", listModelMacros)

	router.GET("/meta/stats", s.stats)

	router.POST("/edit-model/analyze", s.editModelAnalyze)

	router.POST("/direct/analyze", s.analyze)
	router.POST("/direct/check", s.check)
	router.GET("/direct/stub", s.stubFile)

	router.POST("/auth/keys", s.createKey)
	router.DELETE("/auth/keys", s.deleteKey)
	router.POST("/auth/tokens", s.createToken)
	router.DELETE("/auth/tokens", s.deleteToken)

	router.POST("/models", s.createNewModel)
	router.GET("/models", s.listModels)
	router.DELETE("/models/:model-id", s.deleteModel)
	router.GET("/models/:model-id", s.getModel)
	router.PUT("/models/:model-id", s.importModel)
	router.GET("/models/:model-id/data-flow-diagram", s.streamDataFlowDiagram)
	router.GET("/models/:model-id/data-asset-diagram", s.streamDataAssetDiagram)
	router.GET("/models/:model-id/report-pdf", s.streamReportPDF)
	router.GET("/models/:model-id/risks-excel", s.streamRisksExcel)
	router.GET("/models/:model-id/tags-excel", s.streamTagsExcel)
	router.GET("/models/:model-id/risks", s.streamRisksJSON)
	router.GET("/models/:model-id/technical-assets", s.streamTechnicalAssetsJSON)
	router.GET("/models/:model-id/stats", s.streamStatsJSON)
	router.GET("/models/:model-id/analysis", s.analyzeModelOnServerDirectly)

	router.GET("/models/:model-id/cover", s.getCover)
	router.PUT("/models/:model-id/cover", s.setCover)
	router.GET("/models/:model-id/overview", s.getOverview)
	router.PUT("/models/:model-id/overview", s.setOverview)
	//router.GET("/models/:model-id/questions", getQuestions)
	//router.PUT("/models/:model-id/questions", setQuestions)
	router.GET("/models/:model-id/abuse-cases", s.getAbuseCases)
	router.PUT("/models/:model-id/abuse-cases", s.setAbuseCases)
	router.GET("/models/:model-id/security-requirements", s.getSecurityRequirements)
	router.PUT("/models/:model-id/security-requirements", s.setSecurityRequirements)
	//router.GET("/models/:model-id/tags", getTags)
	//router.PUT("/models/:model-id/tags", setTags)

	router.GET("/models/:model-id/data-assets", s.getDataAssets)
	router.POST("/models/:model-id/data-assets", s.createNewDataAsset)
	router.GET("/models/:model-id/data-assets/:data-asset-id", s.getDataAsset)
	router.PUT("/models/:model-id/data-assets/:data-asset-id", s.setDataAsset)
	router.DELETE("/models/:model-id/data-assets/:data-asset-id", s.deleteDataAsset)

	router.GET("/models/:model-id/trust-boundaries", s.getTrustBoundaries)
	//	router.POST("/models/:model-id/trust-boundaries", createNewTrustBoundary)
	//	router.GET("/models/:model-id/trust-boundaries/:trust-boundary-id", getTrustBoundary)
	//	router.PUT("/models/:model-id/trust-boundaries/:trust-boundary-id", setTrustBoundary)
	//	router.DELETE("/models/:model-id/trust-boundaries/:trust-boundary-id", deleteTrustBoundary)

	router.GET("/models/:model-id/shared-runtimes", s.getSharedRuntimes)
	router.POST("/models/:model-id/shared-runtimes", s.createNewSharedRuntime)
	router.GET("/models/:model-id/shared-runtimes/:shared-runtime-id", s.getSharedRuntime)
	router.PUT("/models/:model-id/shared-runtimes/:shared-runtime-id", s.setSharedRuntime)
	router.DELETE("/models/:model-id/shared-runtimes/:shared-runtime-id", s.deleteSharedRuntime)

	s.customRiskRules = model.LoadCustomRiskRules(s.config.GetPluginFolder(), s.config.GetRiskRulePlugins(), config.GetProgressReporter())

	fmt.Println("Threagile is running...")
	_ = router.Run(":" + strconv.Itoa(s.config.GetServerPort())) // listen and serve on 0.0.0.0:8080 or whatever port was specified
}

func (s *server) exampleFile(ginContext *gin.Context) {
	example, err := os.ReadFile(filepath.Join(s.config.GetAppFolder(), "threagile-example-model.yaml"))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	ginContext.Data(http.StatusOK, gin.MIMEYAML, example)
}

func (s *server) stubFile(ginContext *gin.Context) {
	stub, err := os.ReadFile(filepath.Join(s.config.GetAppFolder(), "threagile-stub-model.yaml"))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	ginContext.Data(http.StatusOK, gin.MIMEYAML, s.addSupportedTags(stub)) // TODO use also the MIMEYAML way of serving YAML in model export?
}

func (s *server) addSupportedTags(input []byte) []byte {
	// add distinct tags as "tags_available"
	supportedTags := make(map[string]bool)
	for _, customRule := range s.customRiskRules {
		for _, tag := range customRule.SupportedTags() {
			supportedTags[strings.ToLower(tag)] = true
		}
	}

	for _, rule := range s.builtinRiskRules {
		for _, tag := range rule.SupportedTags() {
			supportedTags[strings.ToLower(tag)] = true
		}
	}

	tags := make([]string, 0, len(supportedTags))
	for t := range supportedTags {
		tags = append(tags, t)
	}
	if len(tags) == 0 {
		return input
	}
	sort.Strings(tags)
	if s.config.GetVerbose() {
		fmt.Print("Supported tags of all risk rules: ")
		for i, tag := range tags {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(tag)
		}
		fmt.Println()
	}
	replacement := "tags_available:"
	for _, tag := range tags {
		replacement += "\n  - " + tag
	}
	return []byte(strings.Replace(string(input), "tags_available:", replacement, 1))
}

func arrayOfStringValues(values []types.TypeEnum) []string {
	result := make([]string, 0)
	for _, value := range values {
		result = append(result, value.String())
	}
	return result
}

func (s *server) stats(ginContext *gin.Context) {
	keyCount, modelCount := 0, 0
	keyFolders, err := os.ReadDir(filepath.Join(s.config.GetServerFolder(), s.config.GetKeyFolder()))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to collect stats",
		})
		return
	}
	for _, keyFolder := range keyFolders {
		if len(keyFolder.Name()) == 128 { // it's a sha512 token hash probably, so count it as token folder for the stats
			keyCount++
			if keyFolder.Name() != filepath.Clean(keyFolder.Name()) {
				ginContext.JSON(http.StatusInternalServerError, gin.H{
					"error": "weird file path",
				})
				return
			}
			modelFolders, err := os.ReadDir(filepath.Join(s.config.GetServerFolder(), s.config.GetKeyFolder(), keyFolder.Name()))
			if err != nil {
				log.Println(err)
				ginContext.JSON(http.StatusInternalServerError, gin.H{
					"error": "unable to collect stats",
				})
				return
			}
			for _, modelFolder := range modelFolders {
				if len(modelFolder.Name()) == 36 { // it's a uuid model folder probably, so count it as model folder for the stats
					modelCount++
				}
			}
		}
	}
	// TODO collect and deliver more stats (old model count?) and health info
	ginContext.JSON(http.StatusOK, gin.H{
		"key_count":     keyCount,
		"model_count":   modelCount,
		"success_count": s.successCount,
		"error_count":   s.errorCount,
	})
}

func handleErrorInServiceCall(err error, ginContext *gin.Context) {
	log.Println(err)
	ginContext.JSON(http.StatusBadRequest, gin.H{
		"error": strings.TrimSpace(err.Error()),
	})
}
