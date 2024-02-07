# Threagile

[![Threagile Community Chat](https://badges.gitter.im/Threagile/community.svg)](https://gitter.im/Threagile/community)

#### Agile Threat Modeling Toolkit
Threagile (see [https://threagile.io](https://threagile.io) for more details) is an open-source toolkit for
agile threat modeling:

It allows to model an architecture with its assets in an agile fashion as a YAML file directly inside the IDE.
Upon execution of the Threagile toolkit all standard risk rules (as well as individual custom rules if present)
are checked against the architecture model.


#### Execution via Docker Container
The easiest way to execute Threagile on the commandline is via its Docker container:

    docker run --rm -it threagile/threagile help

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
    License: Open-Source (MIT License)Version: 1.0.0 ()

    Examples:

    If you want to create an example model (via docker) as a starting point to learn about Threagile just run:
    docker run --rm -it -v "$(pwd)":app/work threagile/threagile create-example-model -output app/work

    If you want to create a minimal stub model (via docker) as a starting point for your own model just run:
    docker run --rm -it -v "$(pwd)":app/work threagile/threagile create-stub-model -output app/work

    If you want to execute Threagile on a model yaml file (via docker):
    docker run --rm -it -v "$(pwd)":app/work threagile/threagile analyze-model -verbose -model -output app/work

    If you want to execute Threagile in interactive mode (via docker):
    docker run --rm -it -v "$(pwd)":app/work threagile/threagile -i -verbose -model -output app/work

    If you want to run Threagile as a server (REST API) on some port (here 8080):
    docker run --rm -it --shm-size=256m  -p 8080:8080 --name --mount 'type=volume,src=threagile-storage,dst=/data,readonly=false' threagile/threagile server --server-port 8080

    If you want to find out about the different enum values usable in the model yaml file:
    docker run --rm -it threagile/threagile list-types

    If you want to use some nice editing help (syntax validation, autocompletion, and live templates) in your favourite IDE:  docker run --rm -it -v "$(pwd)":app/work threagile/threagile create-editing-support -output app/work

    If you want to list all available model macros (which are macros capable of reading a model yaml file, asking you questions in a wizard-style and then update the model yaml file accordingly):
    docker run --rm -it threagile/threagile list-model-macros

    If you want to execute a certain model macro on the model yaml file (here the macro add-build-pipeline):
    docker run --rm -it -v "$(pwd)":app/work threagile/threagile -model app/work/threagile.yaml -output app/work execute-model-macro add-build-pipeline

    Usage:
      threagile [flags]
      threagile [command]

    Available Commands:
      analyze-model            Analyze model
      create-editing-support   Create editing support
      create-example-model     Create example threagile model
      create-stub-model        Create stub threagile model
      execute-model-macro      Execute model macro
      explain-model-macros     Explain model macros
      explain-risk-rules       Detailed explanation of all the risk rules
      explain-types            Print type information (enum values to be used in models)
      help                     Help about any command
      list-model-macros        Print model macros
      list-risk-rules          Print available risk rules
      list-types               Print type information (enum values to be used in models)
      print-license            Print license information
      quit                     quit client
      server                   Run server

    Flags:
          --app-dir string                    app folder (default "/app")
          --background string                 background pdf file (default "background.pdf")
          --config string                     config file
          --custom-risk-rules-plugin string   comma-separated list of plugins file names with custom risk rules to load
          --diagram-dpi int                   DPI used to render: maximum is 300
          --generate-data-asset-diagram       generate data asset diagram (default true)
          --generate-data-flow-diagram        generate data flow diagram (default true)
          --generate-report-pdf               generate report pdf, including diagrams (default true)
          --generate-risks-excel              generate risks excel (default true)
          --generate-risks-json               generate risks json (default true)
          --generate-stats-json               generate stats json (default true)
          --generate-tags-excel               generate tags excel (default true)
          --generate-technical-assets-json    generate technical assets json (default true)
      -h, --help                              help for threagile
          --ignore-orphaned-risk-tracking     ignore orphaned risk tracking (just log them) not matching a concrete risk
      -i, --interactive                       interactive mode
          --model string                      input model yaml file (default "threagile.yaml")
          --output string                     output directory (default ".")
          --plugin-dir string                 plugin folder location (default "/app")
          --raa-run string                    RAA calculation run file name (default "raa_calc")
          --skip-risk-rules string            comma-separated list of risk rules (by their ID) to skip
          --temp-dir string                   temporary folder location (default "/dev/shm")
      -v, --verbose                           verbose output
          --version                           version for threagile

    Additional help topics:
      threagile print-3rd-party-licenses Print 3rd-party license information
      threagile version                  Get version information

    Use "threagile [command] --help" for more information about a command.
