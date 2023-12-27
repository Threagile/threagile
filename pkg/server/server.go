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
	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/security/risks"
	"github.com/threagile/threagile/pkg/security/types"
)

type server struct {
	configuration                  Configuration
	successCount                   int
	errorCount                     int
	globalLock                     sync.Mutex
	throttlerLock                  sync.Mutex
	createdObjectsThrottler        map[string][]int64
	mapTokenHashToTimeoutStruct    map[string]timeoutStruct
	mapFolderNameToTokenHash       map[string]string
	extremeShortTimeoutsForTesting bool
	locksByFolderName              map[string]*sync.Mutex
}

type Configuration struct {
	ServerFolder                string
	AppDir                      string
	BuildTimestamp              string
	KeyDir                      string
	InputFile                   string
	ExecuteModelMacro           string
	ServerPort                  int
	Verbose                     bool
	IgnoreOrphanedRiskTracking  bool
	KeepDiagramSourceFiles      bool
	CustomRiskRules             map[string]*types.CustomRisk
	DefaultGraphvizDPI          int
	TempFolder                  string
	DataFlowDiagramFilenamePNG  string
	DataAssetDiagramFilenamePNG string
	DataFlowDiagramFilenameDOT  string
	DataAssetDiagramFilenameDOT string
	ReportFilename              string
	ExcelRisksFilename          string
	ExcelTagsFilename           string
	JsonRisksFilename           string
	JsonTechnicalAssetsFilename string
	JsonStatsFilename           string
	CustomRiskRulesPlugins      string
	RaaPlugin                   string
	SkipRiskRules               string
	BackupHistoryFilesToKeep    int
}

func RunServer(serverConfiguration Configuration) {
	server := &server{
		configuration:                  serverConfiguration,
		createdObjectsThrottler:        make(map[string][]int64),
		mapTokenHashToTimeoutStruct:    make(map[string]timeoutStruct),
		mapFolderNameToTokenHash:       make(map[string]string),
		extremeShortTimeoutsForTesting: false,
		locksByFolderName:              make(map[string]*sync.Mutex),
	}
	router := gin.Default()
	router.LoadHTMLGlob(filepath.Join(server.configuration.ServerFolder, "server/static/*.html")) // <==
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})
	router.HEAD("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})
	router.StaticFile("/threagile.png", filepath.Join(server.configuration.ServerFolder, "server/static/threagile.png")) // <==
	router.StaticFile("/site.webmanifest", filepath.Join(server.configuration.ServerFolder, "server/static/site.webmanifest"))
	router.StaticFile("/favicon.ico", filepath.Join(server.configuration.ServerFolder, "server/static/favicon.ico"))
	router.StaticFile("/favicon-32x32.png", filepath.Join(server.configuration.ServerFolder, "server/static/favicon-32x32.png"))
	router.StaticFile("/favicon-16x16.png", filepath.Join(server.configuration.ServerFolder, "server/static/favicon-16x16.png"))
	router.StaticFile("/apple-touch-icon.png", filepath.Join(server.configuration.ServerFolder, "server/static/apple-touch-icon.png"))
	router.StaticFile("/android-chrome-512x512.png", filepath.Join(server.configuration.ServerFolder, "server/static/android-chrome-512x512.png"))
	router.StaticFile("/android-chrome-192x192.png", filepath.Join(server.configuration.ServerFolder, "server/static/android-chrome-192x192.png"))

	router.StaticFile("/schema.json", filepath.Join(server.configuration.AppDir, "schema.json"))
	router.StaticFile("/live-templates.txt", filepath.Join(server.configuration.AppDir, "live-templates.txt"))
	router.StaticFile("/openapi.yaml", filepath.Join(server.configuration.AppDir, "openapi.yaml"))
	router.StaticFile("/swagger-ui/", filepath.Join(server.configuration.ServerFolder, "server/static/swagger-ui/index.html"))
	router.StaticFile("/swagger-ui/index.html", filepath.Join(server.configuration.ServerFolder, "server/static/swagger-ui/index.html"))
	router.StaticFile("/swagger-ui/oauth2-redirect.html", filepath.Join(server.configuration.ServerFolder, "server/static/swagger-ui/oauth2-redirect.html"))
	router.StaticFile("/swagger-ui/swagger-ui.css", filepath.Join(server.configuration.ServerFolder, "server/static/swagger-ui/swagger-ui.css"))
	router.StaticFile("/swagger-ui/swagger-ui.js", filepath.Join(server.configuration.ServerFolder, "server/static/swagger-ui/swagger-ui.js"))
	router.StaticFile("/swagger-ui/swagger-ui-bundle.js", filepath.Join(server.configuration.ServerFolder, "server/static/swagger-ui/swagger-ui-bundle.js"))
	router.StaticFile("/swagger-ui/swagger-ui-standalone-preset.js", filepath.Join(server.configuration.ServerFolder, "server/static/swagger-ui/swagger-ui-standalone-preset.js")) // <==

	router.GET("/threagile-example-model.yaml", server.exampleFile)
	router.GET("/threagile-stub-model.yaml", server.stubFile)

	router.GET("/meta/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	router.GET("/meta/version", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"version":         docs.ThreagileVersion,
			"build_timestamp": server.configuration.BuildTimestamp,
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
			"technical_asset_technology":   arrayOfStringValues(types.TechnicalAssetTechnologyValues()),
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

	router.GET("/meta/stats", server.stats)

	router.POST("/direct/analyze", server.analyze)
	router.POST("/direct/check", server.check)
	router.GET("/direct/stub", server.stubFile)

	router.POST("/auth/keys", server.createKey)
	router.DELETE("/auth/keys", server.deleteKey)
	router.POST("/auth/tokens", server.createToken)
	router.DELETE("/auth/tokens", server.deleteToken)

	router.POST("/models", server.createNewModel)
	router.GET("/models", server.listModels)
	router.DELETE("/models/:model-id", server.deleteModel)
	router.GET("/models/:model-id", server.getModel)
	router.PUT("/models/:model-id", server.importModel)
	router.GET("/models/:model-id/data-flow-diagram", server.streamDataFlowDiagram)
	router.GET("/models/:model-id/data-asset-diagram", server.streamDataAssetDiagram)
	router.GET("/models/:model-id/report-pdf", server.streamReportPDF)
	router.GET("/models/:model-id/risks-excel", server.streamRisksExcel)
	router.GET("/models/:model-id/tags-excel", server.streamTagsExcel)
	router.GET("/models/:model-id/risks", server.streamRisksJSON)
	router.GET("/models/:model-id/technical-assets", server.streamTechnicalAssetsJSON)
	router.GET("/models/:model-id/stats", server.streamStatsJSON)
	router.GET("/models/:model-id/analysis", server.analyzeModelOnServerDirectly)

	router.GET("/models/:model-id/cover", server.getCover)
	router.PUT("/models/:model-id/cover", server.setCover)
	router.GET("/models/:model-id/overview", server.getOverview)
	router.PUT("/models/:model-id/overview", server.setOverview)
	//router.GET("/models/:model-id/questions", getQuestions)
	//router.PUT("/models/:model-id/questions", setQuestions)
	router.GET("/models/:model-id/abuse-cases", server.getAbuseCases)
	router.PUT("/models/:model-id/abuse-cases", server.setAbuseCases)
	router.GET("/models/:model-id/security-requirements", server.getSecurityRequirements)
	router.PUT("/models/:model-id/security-requirements", server.setSecurityRequirements)
	//router.GET("/models/:model-id/tags", getTags)
	//router.PUT("/models/:model-id/tags", setTags)

	router.GET("/models/:model-id/data-assets", server.getDataAssets)
	router.POST("/models/:model-id/data-assets", server.createNewDataAsset)
	router.GET("/models/:model-id/data-assets/:data-asset-id", server.getDataAsset)
	router.PUT("/models/:model-id/data-assets/:data-asset-id", server.setDataAsset)
	router.DELETE("/models/:model-id/data-assets/:data-asset-id", server.deleteDataAsset)

	router.GET("/models/:model-id/trust-boundaries", server.getTrustBoundaries)
	//	router.POST("/models/:model-id/trust-boundaries", createNewTrustBoundary)
	//	router.GET("/models/:model-id/trust-boundaries/:trust-boundary-id", getTrustBoundary)
	//	router.PUT("/models/:model-id/trust-boundaries/:trust-boundary-id", setTrustBoundary)
	//	router.DELETE("/models/:model-id/trust-boundaries/:trust-boundary-id", deleteTrustBoundary)

	router.GET("/models/:model-id/shared-runtimes", server.getSharedRuntimes)
	router.POST("/models/:model-id/shared-runtimes", server.createNewSharedRuntime)
	router.GET("/models/:model-id/shared-runtimes/:shared-runtime-id", server.getSharedRuntime)
	router.PUT("/models/:model-id/shared-runtimes/:shared-runtime-id", server.setSharedRuntime)
	router.DELETE("/models/:model-id/shared-runtimes/:shared-runtime-id", server.deleteSharedRuntime)

	fmt.Println("Threagile server running...")
	_ = router.Run(":" + strconv.Itoa(server.configuration.ServerPort)) // listen and serve on 0.0.0.0:8080 or whatever port was specified
}

func (s *server) exampleFile(ginContext *gin.Context) {
	example, err := os.ReadFile(filepath.Join(s.configuration.AppDir, "threagile-example-model.yaml"))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	ginContext.Data(http.StatusOK, gin.MIMEYAML, example)
}

func (s *server) stubFile(ginContext *gin.Context) {
	stub, err := os.ReadFile(filepath.Join(s.configuration.AppDir, "threagile-stub-model.yaml"))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	ginContext.Data(http.StatusOK, gin.MIMEYAML, s.addSupportedTags(stub)) // TODO use also the MIMEYAML way of serving YAML in model export?
}

func (s *server) addSupportedTags(input []byte) []byte {
	// add distinct tags as "tags_available"
	supportedTags := make(map[string]bool)
	for _, customRule := range s.configuration.CustomRiskRules {
		for _, tag := range customRule.Tags {
			supportedTags[strings.ToLower(tag)] = true
		}
	}

	for _, rule := range risks.GetBuiltInRiskRules() {
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
	if s.configuration.Verbose {
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
	keyFolders, err := os.ReadDir(filepath.Join(s.configuration.ServerFolder, s.configuration.KeyDir))
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
			modelFolders, err := os.ReadDir(filepath.Join(s.configuration.ServerFolder, s.configuration.KeyDir, keyFolder.Name()))
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
