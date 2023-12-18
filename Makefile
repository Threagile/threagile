# Files and Folders
ASSET_DIR		= $(HOME)/.threagile
BIN_DIR			= $(HOME)/bin
ASSETS			= 							\
	LICENSE.txt 							\
	report/template/background.pdf 			\
	support/openapi.yaml 					\
	support/schema.json 					\
	support/live-templates.txt				\
	server
BIN				= 							\
	raa 									\
	raa_dummy 								\
	risk_demo 								\
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
.phony: all install clean uninstall

default: all

prep:
	env GO111MODULE=on go mod vendor
	$(MKDIR) bin

all: prep $(addprefix bin/,$(BIN))

clean:
	$(RM) bin vendor

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

bin/raa: raa/raa/raa.go
	$(GO) build $(GOFLAGS) -o $@ $<

bin/raa_dummy: raa/dummy/dummy.go
	$(GO) build $(GOFLAGS) -o $@ $<

bin/risk_demo: risks/custom/demo/demo-rule.go
	$(GO) build $(GOFLAGS) -o $@ $<

bin/threagile: main.go
	$(GO) build $(GOFLAGS) -o $@ $<
