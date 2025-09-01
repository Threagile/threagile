# Threagile

[![Threagile Community Chat](https://badges.gitter.im/Threagile/community.svg)](https://gitter.im/Threagile/community)

## Agile Threat Modeling Toolkit
Threagile (see [threagile.io](https://threagile.io) for more details) is an open-source toolkit for
agile threat modeling:

It allows to model an architecture with its assets in an agile fashion as a YAML file directly inside the IDE.
Upon execution of the Threagile toolkit all standard risk rules (as well as individual custom rules if present)
are checked against the architecture model. You can find more information about model schema [here](./docs/model.md).

The tool have various [commands](./docs/commands.md) and is highly configurable via [flags](./docs/flags.md) and [config](./docs/config.md).

We know that modifying yaml file via text editor may be tough and to simplify it we introduced:

- [includes](./docs/includes.md)
- [macros](./docs/macros.md)

Efforts on UI are ongoing and there are few attempts to do it although that is far from being ready.

[Here](./docs/how-to.md) may be useful use cases on how others are using the tool and may be helpful to simplify onboarding of Threagile tool for your team.

Threagile now contains 12 privacy rules that detect privacy risks for a given architecture model (in a YAML file). These privacy rules detect risks which could be classified under threat categories like `Linking`, `Identifying`, `Data Disclosure`, `Unawareness` and `Non-compliance` found in the [LINDDUN](https://linddun.org/) privacy threat modeling framework. More details can be found in the [privacy-rules doc](./docs/privacy-rules.md).

## Execution via Docker Container
The easiest way to execute Threagile on the commandline is via its Docker container:

```shell
    docker run --rm -it threagile/threagile --help
```

Which will give you an output with possible flags that can be used with Threagile.

```
      _____ _                          _ _
     |_   _| |__  _ __ ___  __ _  __ _(_) | ___
       | | | '_ \| '__/ _ \/ _` |/ _` | | |/ _ \
       | | | | | | | |  __/ (_| | (_| | | |  __/
       |_| |_| |_|_|  \___|\__,_|\__, |_|_|\___|
                                 |___/
    Threagile - Agile Threat Modeling


    Documentation: https://threagile.io
    Docker Images: https://hub.docker.com/r/threagile/threagile
    Sourcecode: https://github.com/threagile
    License: Open-Source (MIT License)
    Version: 1.0.0 (20231104141112)


    Usage: threagile [options]


    Options:

      -background string
        	background pdf file (default "background.pdf")
      -create-editing-support
        	just create some editing support stuff in the output directory
      -create-example-model
        	just create an example model named threagile-example-model.yaml in the output directory
      -create-stub-model
        	just create a minimal stub model named threagile-stub-model.yaml in the output directory
      -custom-risk-rules-plugins string
        	comma-separated list of plugins (.so shared object) file names with custom risk rules to load
      -diagram-dpi int
        	DPI used to render: maximum is 240 (default 120)
      -execute-model-macro string
        	Execute model macro (by ID)
      -generate-data-asset-diagram
        	generate data asset diagram (default true)
      -generate-data-flow-diagram
        	generate data-flow diagram (default true)
      -generate-report-pdf
        	generate report pdf, including diagrams (default true)
      -generate-risks-excel
        	generate risks excel (default true)
      -generate-risks-json
        	generate risks json (default true)
      -generate-stats-json
        	generate stats json (default true)
      -generate-tags-excel
        	generate tags excel (default true)
      -generate-technical-assets-json
        	generate technical assets json (default true)
      -ignore-orphaned-risk-tracking
        	ignore orphaned risk tracking (just log them) not matching a concrete risk
      -list-model-macros
        	print model macros
      -list-risk-rules
        	print risk rules
      -list-types
        	print type information (enum values to be used in models)
      -model string
        	input model yaml file (default "threagile.yaml")
      -output string
        	output directory (default ".")
      -print-3rd-party-licenses
        	print 3rd-party license information
      -print-license
        	print license information
      -server int
        	start a server (instead of commandline execution) on the given port
      -skip-risk-rules string
        	comma-separated list of risk rules (by their ID) to skip
      -verbose
        	verbose output
      -version
        	print version


    Examples:

    If you want to create an example model (via docker) as a starting point to learn about Threagile just run:
     docker run --rm -it -v "$(pwd)":/app/work threagile/threagile --create-example-model --output /app/work

    If you want to create a minimal stub model (via docker) as a starting point for your own model just run:
     docker run --rm -it -v "$(pwd)":/app/work threagile/threagile --create-stub-model --output /app/work

    If you want to execute Threagile on a model yaml file (via docker):
     docker run --rm -it -v "$(pwd)":/app/work threagile/threagile --verbose --model /app/work/threagile.yaml --output /app/work

    If you want to run Threagile as a server (REST API) on some port (here 8080):
     docker run --rm -it --shm-size=256m -p 8080:8080 --name threagile-server --mount 'type=volume,src=threagile-storage,dst=/data,readonly=false' threagile/threagile -server 8080

    If you want to find out about the different enum values usable in the model yaml file:
     docker run --rm -it threagile/threagile -list-types

    If you want to use some nice editing help (syntax validation, autocompletion, and live templates) in your favourite IDE:
     docker run --rm -it -v "$(pwd)":/app/work threagile/threagile --create-editing-support --output /app/work

    If you want to list all available model macros (which are macros capable of reading a model yaml file, asking you questions in a wizard-style and then update the model yaml file accordingly):
     docker run --rm -it threagile/threagile -list-model-macros

    If you want to execute a certain model macro on the model yaml file (here the macro add-build-pipeline):
     docker run --rm -it -v "$(pwd)":/app/work threagile/threagile --model /app/work/threagile.yaml --output /app/work --execute-model-macro add-build-pipeline
```

## Releases

The information about releases can be found at [releases page](./docs/releases.md).

## Contribution

You are very welcome to contribute into the project in any way. If you'd like to add new feature or fix the bug in the code base  please follow [contribution guide](./CONTRIBUTING.md).

Otherwise please create GitHub discussion or issue and contributors will find some time to respond.
