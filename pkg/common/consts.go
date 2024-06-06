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

	DefaultDiagramDPI               = 100
	DefaultGraphvizDPI              = 120
	MinGraphvizDPI                  = 20
	MaxGraphvizDPI                  = 300
	DefaultBackupHistoryFilesToKeep = 50
)

const (
	AnalyzeModelCommand         = "analyze-model"
	CreateExampleModelCommand   = "create-example-model"
	CreateStubModelCommand      = "create-stub-model"
	CreateEditingSupportCommand = "create-editing-support"
	ListTypesCommand            = "list-types"
	ListRiskRulesCommand        = "list-risk-rules"
	ListModelMacrosCommand      = "list-model-macros"
	Print3rdPartyCommand        = "print-3rd-party-licenses"
	PrintLicenseCommand         = "print-license"

	CreateCommand       = "create"
	ExplainCommand      = "explain"
	ListCommand         = "list"
	PrintCommand        = "print"
	QuitCommand         = "quit"
	RunCommand          = "run"
	PrintVersionCommand = "version"
)

const (
	EditingSupportItem = "editing-support"
	ExampleItem        = "example"
	LicenseItem        = "license"
	MacrosItem         = "macros"
	ModelItem          = "model"
	RiskItem           = "risk"
	RulesItem          = "rules"
	StubItem           = "stub"
	TypesItem          = "types"
)
