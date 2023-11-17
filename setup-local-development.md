# Threagile develop locally 

Threagile is built using Go, to render diagrams it's using GraphViz. 

## Prerequisites

- [Go 1.19+](https://go.dev/)
- [GraphViz](https://graphviz.org/download/)

## Build plugins

To make rules extendable for customers Threagile is using conception of [plugins](https://pkg.go.dev/plugin). Default plugin is built from [raa.go](raa/raa/raa.go), and this is essential to run basic version. Note if you'd like to build it locally it would be enough to run command from your terminal 

```
go build -buildmode=plugin -gcflags "all=-N -l" -o raa.so raa/raa/raa.go
```

Which is quite different from what is used in release version (see code of [Docker](Dockerfile)) but close enough for local development

## Debug with VSCode

To make it debuggable from VS Code you can add this to your launch.json: 

```
{
    "version": "0.2.0",
    "configurations": [        
        {
          "name": "Launch Threagile",
          "type": "go",
          "request": "launch",
          "mode": "debug",
          "program": "${workspaceFolder}",
          "args": [
            "--tmp-folder",
            "./tmp",
            "--background",
            "./report/template/background.pdf"
          ]
        }
    ]
}
```

## Debug with GoLand

TBD 

## Debug with Sublime Text

TBD 

## Debug with Vim

TBD 