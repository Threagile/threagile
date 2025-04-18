# Files and Folders
ASSET_DIR		= $(HOME)/.threagile
BIN_DIR			= $(HOME)/bin
ASSETS			= 							\
	LICENSE.txt 							\
	report/template/background.pdf 			\
	support/openapi.yaml 					\
	support/schema.json 					\
	support/live-templates.txt				\
	pkg/types/technologies.yaml	\
	server
BIN				= 							\
	risk_demo	 							\
	threagile

# Commands and Flags
GOFLAGS	= -a -ldflags="-s -w -X main.buildTimestamp=$(shell date '+%Y%m%d%H%M%S')"
GO		= env GO111MODULE=on go
MKDIR	= mkdir -p
CP		= cp -r
RM		= rm -rf
GOSEC	= /opt/homebrew/bin/gosec

# Targets
.phony: all prep test-all clean tidy install uninstall gosec gv dist update lint

default: all

all: prep test-all $(addprefix bin/,$(BIN))

prep:
	@# env GO111MODULE=on go mod vendor
	$(MKDIR) bin

test-all:
	$(GO) test ./...

clean:
	$(RM) bin vendor

tidy: clean
	$(RM) .DS_Store
	$(RM) just-for-docker-build-?.txt
	$(RM) data-asset-diagram.* data-flow-diagram.*
	$(RM) report.pdf risks.xlsx tags.xlsx risks.json technical-assets.json stats.json
	$(RM) *.exe *.exe~ *.dll *.so *.dylibc *.test *.out

install: all
	mkdir -p $(BIN_DIR) $(ASSET_DIR)
	$(CP) $(addprefix bin/,$(BIN)) $(BIN_DIR)
	$(CP) $(ASSETS) $(ASSET_DIR)
	$(CP) demo/example/threagile.yaml $(ASSET_DIR)/threagile-example-model.yaml
	$(CP) demo/stub/threagile.yaml $(ASSET_DIR)/threagile-stub-model.yaml

uninstall:
	$(RM) $(addprefix $(BIN_DIR)/,$(BIN))
	$(RM) $(ASSET_DIR)

gosec:
	$(GOSEC) ./...

dist: update gosec lint all

update:
	go get -u ./...
	go mod tidy

lint:
	$(if $(shell which golangci-lint), golangci-lint run ./..., @echo "No golangci-lint found, consider running: \n   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest")

gv: out/tmp/diagram.png

out/tmp/diagram.png: out/tmp/diagram.gv
	dot -Tpng $< -o $@

bin/risk_demo: cmd/risk_demo/main.go
	$(GO) build $(GOFLAGS) -o $@ $<

bin/threagile: cmd/threagile/main.go
	$(GO) build $(GOFLAGS) -o $@ $<
