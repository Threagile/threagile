# Contributing to Threagile

:+1::tada: First of all, thanks for taking the time to contribute! :tada::+1:

All your contributions are very welcome, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

Thank you so much! :clap:

## Development

Before running the project please install

- [go 1.21.0](https://go.dev/doc/install)
- [Docker](https://docs.docker.com/engine/install/)
- [pre-commit](https://pre-commit.com/)
- [golangci-lint](https://golangci-lint.run/usage/install/#local-installation)
- [goimports](https://pkg.go.dev/golang.org/x/tools/cmd/goimports)

Main program is [threagile](./cmd/threagile/main.go).

### Development with Visual Studio Code

To run the code with VS Code add launch.json with this content and simply use ```Run -> Start Debugging```/```Run -> Start Without Debugging```:

```
{
    "version": "0.2.0",
    "configurations": [
        {
          "name": "Launch Threagile",
          "type": "go",
          "request": "launch",
          "mode": "debug",
          "console": "integratedTerminal",
          "program": "${workspaceFolder}/cmd/threagile",
          "args": [
            "help",
            "--ignore-orphaned-risk-tracking",
            "--model",
            "./threagile.yaml",
            "--app-dir",
            "directory_with_support_files",
            "--temp-dir",
            "./",
            "-v"
          ]
        }
    ]
}
```

```directory_with_support_files``` is a directory where support files are located:

```
app/
├─ [background.pdf](./report/template/background.pdf)
├─ [LICENSE.txt](./LICENSE.txt)
├─ [live-templates.txt](./support/live-templates.txt)
├─ [openapi.yaml](./support/openapi.yaml)
├─ [schema.json](./support/schema.json)
├─ [threagile-example-model.yaml](./demo/example/threagile.yaml)
├─ [threagile-stub-model.yaml](./demo/stub/threagile.yaml)
```

## Contribution

To contribute the code simply make changes and create pull request. There is no strict rules about pull requests format like [this](https://www.pullrequest.com/blog/writing-a-great-pull-request-description/) however please take into consideration:

- it is easy to understand what the code change is achieving and why it was added
- new change is covered with unit tests

Before commiting the code please install [pre-commit](https://pre-commit.com/) and run ```pre-commit install``` to ensure that checks are running every time before commit.
