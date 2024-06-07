package threagile

import (
	"os"

	"github.com/spf13/cobra"
)

func (what *Threagile) initQuit() *Threagile {
	quit := &cobra.Command{
		Use:     QuitCommand,
		Short:   "quit client",
		Aliases: []string{"exit", "bye", "x", "q"},
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(0)
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	what.rootCmd.AddCommand(quit)

	return what
}
