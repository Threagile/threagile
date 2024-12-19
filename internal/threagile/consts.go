package threagile

const (
	TempDir   = "/dev/shm"
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
	ReportLogoImagePath         = "report/threagile-logo.png"
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

const (
	ThreagileVersion = "1.0.0" // Also update into example and stub model files and openapi.yaml
	Logo             = "  _____ _                          _ _      \n |_   _| |__  _ __ ___  __ _  __ _(_) | ___ \n   | | | '_ \\| '__/ _ \\/ _` |/ _` | | |/ _ \\\n   | | | | | | | |  __/ (_| | (_| | | |  __/\n   |_| |_| |_|_|  \\___|\\__,_|\\__, |_|_|\\___|\n                             |___/        " +
		"\nThreagile - Agile Threat Modeling"
	VersionText = "Documentation: https://threagile.io\n" +
		"Docker Images: https://hub.docker.com/r/threagile/threagile\n" +
		"Sourcecode: https://github.com/threagile\n" +
		"License: Open-Source (MIT License)" +
		"Version: " + ThreagileVersion + " (%v)"
	Examples = "Examples:\n\n" +
		"If you want to create an example model (via docker) as a starting point to learn about Threagile just run: \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile " + CreateExampleModelCommand + " --output app/work \n\n" +
		"If you want to create a minimal stub model (via docker) as a starting point for your own model just run: \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile " + CreateStubModelCommand + " --output app/work \n\n" +
		"If you want to execute Threagile on a model yaml file (via docker):  \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile analyze-model --verbose --model --output app/work \n\n" +
		"If you want to execute Threagile in interactive mode (via docker):  \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile -i --verbose --model --output app/work \n\n" +
		"If you want to run Threagile as a server (REST API) on some port (here 8080):  \n" +
		" docker run --rm -it --shm-size=256m  -p 8080:8080 --mount 'type=volume,src=threagile-storage,dst=/data,readonly=false' threagile/threagile server --server-port 8080 \n\n" +
		"If you want to find out about the different enum values usable in the model yaml file: \n" +
		" docker run --rm -it threagile/threagile " + ListTypesCommand + "\n\n" +
		"If you want to use some nice editing help (syntax validation, autocompletion, and live templates) in your favourite IDE: \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile " + CreateEditingSupportCommand + " --output app/work\n\n" +
		"If you want to list all available model macros (which are macros capable of reading a model yaml file, asking you questions in a wizard-style and then update the model yaml file accordingly): \n" +
		" docker run --rm -it threagile/threagile " + ListModelMacrosCommand + " \n\n" +
		"If you want to execute a certain model macro on the model yaml file (here the macro add-build-pipeline): \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile --model app/work/threagile.yaml --output app/work execute-model-macro add-build-pipeline"
	ThirdPartyLicenses = " - golang (Google Go License): https://golang.org/LICENSE\n" +
		" - go-yaml (MIT License): https://github.com/go-yaml/yaml/blob/v3/LICENSE\n" +
		" - graphviz (CPL License): https://graphviz.gitlab.io/license/\n" +
		" - gofpdf (MIT License): https://github.com/jung-kurt/gofpdf/blob/master/LICENSE\n" +
		" - go-chart (MIT License): https://github.com/wcharczuk/go-chart/blob/master/LICENSE\n" +
		" - excelize (BSD License): https://github.com/qax-os/excelize/blob/master/LICENSE\n" +
		" - graphics-go (BSD License): https://github.com/BurntSushi/graphics-go/blob/master/LICENSE\n" +
		" - google-uuid (BSD License): https://github.com/google/uuid/blob/master/LICENSE\n" +
		" - gin-gonic (MIT License): https://github.com/gin-gonic/gin/blob/master/LICENSE\n" +
		" - cobra-cli (Apache License): https://github.com/spf13/cobra-cli/blob/main/LICENSE.txt\n"
)
