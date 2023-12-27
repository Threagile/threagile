package common

const (
	TempDir   = "/dev/shm" // TODO: make configurable via cmdline arg?
	AppDir    = "/app"
	BinDir    = "/app"
	DataDir   = "/data"
	OutputDir = "."
	ServerDir = "/server"
	KeyDir    = "keys"

	InputFile                              = "threagile.yaml"
	ReportFilename                         = "report.pdf"
	ExcelRisksFilename                     = "risks.xlsx"
	ExcelTagsFilename                      = "tags.xlsx"
	JsonRisksFilename                      = "risks.json"
	JsonTechnicalAssetsFilename            = "technical-assets.json"
	JsonStatsFilename                      = "stats.json"
	TemplateFilename                       = "background.pdf"
	DataFlowDiagramFilenameDOT             = "data-flow-diagram.gv"
	DataFlowDiagramFilenamePNG             = "data-flow-diagram.png"
	DataAssetDiagramFilenameDOT            = "data-asset-diagram.gv"
	DataAssetDiagramFilenamePNG            = "data-asset-diagram.png"
	GraphvizDataFlowDiagramConversionCall  = "render-data-flow-diagram.sh"
	GraphvizDataAssetDiagramConversionCall = "render-data-asset-diagram.sh"

	RAAPluginName = "raa_calc"

	DefaultGraphvizDPI              = 120
	MinGraphvizDPI                  = 20
	MaxGraphvizDPI                  = 300
	DefaultBackupHistoryFilesToKeep = 50
)

const (
	ServerPortCommand                  = "server-port"
	CreateExampleModelCommand          = "create-example-model"
	CreateStubModelCommand             = "create-stub-model"
	CreateEditingSupportCommand        = "create-editing-support"
	GenerateDataFlowDiagramCommand     = "generate-data-flow-diagram"
	GenerateDataAssetDiagramCommand    = "generate-data-asset-diagram"
	GenerateRisksJSONCommand           = "generate-risks-json"
	GenerateTechnicalAssetsJSONCommand = "generate-technical-assets-json"
	GenerateStatsJSONCommand           = "generate-stats-json"
	GenerateRisksExcelCommand          = "generate-risks-excel"
	GenerateTagsExcelCommand           = "generate-tags-excel"
	GenerateReportPDFCommand           = "generate-report-pdf"
	PrintVersionCommand                = "version"
	ListTypesCommand                   = "list-types"
	ListRiskRulesCommand               = "list-risk-rules"
	ListModelMacrosCommand             = "list-model-macros"
	ExplainTypesCommand                = "explain-types"
	ExplainRiskRulesCommand            = "explain-risk-rules"
	ExplainModelMacrosCommand          = "explain-model-macros"
	Print3rdPartyCommand               = "print-3rd-party-licenses"
	PrintLicenseCommand                = "print-license"
)
