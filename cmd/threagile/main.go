package main

import (
	threagile "github.com/threagile/threagile/internal/threagile"
)

const (
	buildTimestamp = ""
)

func main() {
	// TODO: uncomment below as soon as refactoring is finished - everything will go through rootCmd.Execute
	threagile.Execute()

	// TODO: remove below as soon as refactoring is finished - everything will go through rootCmd.Execute
	// for now it's fine to have as frequently uncommented to see the actual behaviour
	// config, commands := threagile.ParseCommandlineArgs(buildTimestamp)
	// if config.ServerPort > 0 {
	// 	server.RunServer(&config)
	// } else {
	// 	threagile.DoIt(&config, &commands)
	// }
}
