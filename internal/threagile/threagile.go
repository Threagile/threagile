package threagile

import (
	"github.com/spf13/cobra"
	"os"
)

type Threagile struct {
	flags          Flags
	rootCmd        *cobra.Command
	buildTimestamp string
}

func (what *Threagile) Execute() {
	err := what.rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func (what *Threagile) Init(buildTimestamp string) *Threagile {
	what.buildTimestamp = buildTimestamp
	return what.initRoot().initAbout().initRules().initExamples().initMacros().initTypes().initAnalyze().initServer().initQuit()
}
