/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package docs

import "github.com/threagile/threagile/pkg/common"

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
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile " + common.CreateExampleModelCommand + " -output app/work \n\n" +
		"If you want to create a minimal stub model (via docker) as a starting point for your own model just run: \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile " + common.CreateStubModelCommand + " -output app/work \n\n" +
		"If you want to execute Threagile on a model yaml file (via docker):  \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile analyze-model -verbose -model -output app/work \n\n" +
		"If you want to execute Threagile in interactive mode (via docker):  \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile -i -verbose -model -output app/work \n\n" +
		"If you want to run Threagile as a server (REST API) on some port (here 8080):  \n" +
		" docker run --rm -it --shm-size=256m  -p 8080:8080 --name --mount 'type=volume,src=threagile-storage,dst=/data,readonly=false' threagile/threagile server --server-port 8080 \n\n" +
		"If you want to find out about the different enum values usable in the model yaml file: \n" +
		" docker run --rm -it threagile/threagile " + common.ListTypesCommand + "\n\n" +
		"If you want to use some nice editing help (syntax validation, autocompletion, and live templates) in your favourite IDE: " +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile " + common.CreateEditingSupportCommand + " -output app/work\n\n" +
		"If you want to list all available model macros (which are macros capable of reading a model yaml file, asking you questions in a wizard-style and then update the model yaml file accordingly): \n" +
		" docker run --rm -it threagile/threagile " + common.ListModelMacrosCommand + " \n\n" +
		"If you want to execute a certain model macro on the model yaml file (here the macro add-build-pipeline): \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile -model app/work/threagile.yaml -output app/work execute-model-macro add-build-pipeline"
	ThirdPartyLicenses = " - golang (Google Go License): https://golang.org/LICENSE\n" +
		" - go-yaml (MIT License): https://github.com/go-yaml/yaml/blob/v3/LICENSE\n" +
		" - graphviz (CPL License): https://graphviz.gitlab.io/license/\n" +
		" - gofpdf (MIT License): https://github.com/jung-kurt/gofpdf/blob/master/LICENSE\n" +
		" - go-chart (MIT License): https://github.com/wcharczuk/go-chart/blob/master/LICENSE\n" +
		" - excelize (BSD License): https://github.com/qax-os/excelize/blob/master/LICENSE\n" +
		" - graphics-go (BSD License): https://github.com/BurntSushi/graphics-go/blob/master/LICENSE\n" +
		" - google-uuid (BSD License): https://github.com/google/uuid/blob/master/LICENSE\n" +
		" - gin-gonic (MIT License): https://github.com/gin-gonic/gin/blob/master/LICENSE\n" +
		" - swagger-ui (Apache License): https://swagger.io/license/\n" +
		" - cobra-cli (Apache License): https://github.com/spf13/cobra-cli/blob/main/LICENSE.txt\n"
)
