package threagile

import (
	"os"

	"github.com/spf13/cobra"
)

type Threagile struct {
	flags          Flags
	config         *Config
	rootCmd        *cobra.Command
	buildTimestamp string
}

func (what *Threagile) Execute() {
	err := what.rootCmd.Execute()
	if err != nil {
		what.rootCmd.Println(err)
		os.Exit(1)
	}

	if what.config.GetServerMode() {
		serverError := what.runServer()
		what.rootCmd.Println(serverError)
	} else if what.config.GetInteractive() {
		what.run(what.rootCmd, nil)
	}
}

func (what *Threagile) Init(buildTimestamp string) *Threagile {
	what.buildTimestamp = buildTimestamp
	return what.initRoot().initImport().initAnalyze().initCreate().initExecute().initExplain().initList().initPrint().initQuit().initServer().initVersion().processSystemArgs(what.rootCmd)
}
