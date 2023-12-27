package main

import (
	"github.com/threagile/threagile/internal/threagile"
	"github.com/threagile/threagile/pkg/server"
)

const (
	buildTimestamp = ""
)

// === Error handling stuff ========================================

func main() {
	// TODO: uncomment below as soon as refactoring is finished - everything will go through rootCmd.Execute
	// threagile.Execute()

	// TODO: remove below as soon as refactoring is finished - everything will go through rootCmd.Execute
	// for now it's fine to have as frequently uncommented to see the actual behaviour
	context := new(threagile.Context).Defaults(buildTimestamp).ParseCommandlineArgs()
	if context.ServerMode {
		server.RunServer(context.Config)
	} else {
		context.DoIt()
	}
}
