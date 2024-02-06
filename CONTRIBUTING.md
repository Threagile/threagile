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

## Contribution

To contribute the code simply make changes and create pull request. There is no strict rules about pull requests format like [this](https://www.pullrequest.com/blog/writing-a-great-pull-request-description/) however please take into consideration:

- it is easy to understand what the code change is achieving and why it was added
- new change is covered with unit tests

Before commiting the code please install [pre-commit](https://pre-commit.com/) and run ```pre-commit install``` to ensure that checks are running every time before commit.
