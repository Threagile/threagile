# Files and Folders
ASSET_DIR		= $(HOME)/.threagile
BIN_DIR			= $(HOME)/bin
ASSETS			= 							\
	LICENSE.txt 							\
	pkg/report/template/background.pdf 		\
	support/openapi.yaml 					\
	support/schema.json 					\
	support/live-templates.txt				\
	server
BIN				= 							\
	raa_calc 								\
	raa_dummy 								\
	risk_demo_rule 							\
	threagile
SCRIPTS			= 							\
	support/render-data-asset-diagram.sh 	\
	support/render-data-flow-diagram.sh

# Commands and Flags
GOFLAGS	= -a -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')"
GO		= env GO111MODULE=on go
MKDIR	= mkdir -p
CP		= cp -r
RM		= rm -rf

# Targets
.phony: all run_tests install clean uninstall

default: all

prep:
	env GO111MODULE=on go mod vendor
	$(MKDIR) bin

run_tests:
	$(GO) test ./...

all: prep run_tests $(addprefix bin/,$(BIN))

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
	$(CP) $(SCRIPTS) $(BIN_DIR)
	$(CP) $(ASSETS) $(ASSET_DIR)
	$(CP) demo/example/threagile.yaml $(ASSET_DIR)/threagile-example-model.yaml
	$(CP) demo/stub/threagile.yaml $(ASSET_DIR)/threagile-stub-model.yaml

uninstall:
	$(RM) $(addprefix $(BIN_DIR)/,$(BIN))
	$(RM) $(addprefix $(BIN_DIR)/,$(notdir $(SCRIPTS)))
	$(RM) $(ASSET_DIR)

bin/raa_calc: cmd/raa/main.go
	$(GO) build $(GOFLAGS) -o $@ $<

bin/raa_dummy: cmd/raa_dummy/main.go
	$(GO) build $(GOFLAGS) -o $@ $<

bin/risk_demo_rule: cmd/risk_demo/main.go
	$(GO) build $(GOFLAGS) -o $@ $<

bin/threagile: cmd/threagile/main.go
	$(GO) build $(GOFLAGS) -o $@ $<
