package common

const (
	TempDir   = "/dev/shm" // TODO: make configurable via cmdline arg?
	AppDir    = "/app"
	PluginDir = "/app"
	DataDir   = "/data"
	OutputDir = "."
	ServerDir = "/server"
	KeyDir    = "keys"

	DefaultServerPort = 8080

	InputFile                   = "threagile.yaml"
	ReportFilename              = "report.pdf"
	ExcelRisksFilename          = "risks.xlsx"
	ExcelTagsFilename           = "tags.xlsx"
	JsonRisksFilename           = "risks.json"
	JsonTechnicalAssetsFilename = "technical-assets.json"
	JsonStatsFilename           = "stats.json"
	TemplateFilename            = "background.pdf"
	DataFlowDiagramFilenameDOT  = "data-flow-diagram.gv"
	DataFlowDiagramFilenamePNG  = "data-flow-diagram.png"
	DataAssetDiagramFilenameDOT = "data-asset-diagram.gv"
	DataAssetDiagramFilenamePNG = "data-asset-diagram.png"

	RAAPluginName = "raa_calc"

	DefaultGraphvizDPI              = 120
	MinGraphvizDPI                  = 20
	MaxGraphvizDPI                  = 300
	DefaultBackupHistoryFilesToKeep = 50
)

const (
	QuitCommand                 = "quit"
	AnalyzeModelCommand         = "analyze-model"
	CreateExampleModelCommand   = "create-example-model"
	CreateStubModelCommand      = "create-stub-model"
	CreateEditingSupportCommand = "create-editing-support"
	PrintVersionCommand         = "version"
	ListTypesCommand            = "list-types"
	ListRiskRulesCommand        = "list-risk-rules"
	ListModelMacrosCommand      = "list-model-macros"
	ExplainTypesCommand         = "explain-types"
	ExplainRiskRulesCommand     = "explain-risk-rules"
	ExplainRiskCommand          = "explain-risk"
	ExplainModelMacrosCommand   = "explain-model-macros"
	Print3rdPartyCommand        = "print-3rd-party-licenses"
	PrintLicenseCommand         = "print-license"
)
