package threagile

import (
	"os"

	"github.com/spf13/cobra"
)

type Threagile struct {
	flags          Flags
	rootCmd        *cobra.Command
	buildTimestamp string
}

func (what *Threagile) Execute() {
	err := what.rootCmd.Execute()
	if err != nil {
		what.rootCmd.Println(err)
		os.Exit(1)
	}
}

func (what *Threagile) Init(buildTimestamp string) *Threagile {
	what.buildTimestamp = buildTimestamp
	return what.initRoot().initAnalyze().initCreate().initExecute().initExplain().initList().initPrint().initQuit().initServer().initVersion()
}
