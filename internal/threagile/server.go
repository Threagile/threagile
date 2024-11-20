package threagile

import (
	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/server"
)

func (what *Threagile) initServer() *Threagile {
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Run server",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			return what.runServer()
		},
	}

	serverCmd.PersistentFlags().IntVar(&what.flags.ServerPortValue, serverPortFlagName, what.config.GetServerPort(), "server port")
	serverCmd.PersistentFlags().StringVar(&what.flags.ServerFolderValue, serverDirFlagName, what.config.GetDataFolder(), "base folder for server mode (default: "+DataDir+")")

	what.rootCmd.AddCommand(serverCmd)

	return what
}

func (what *Threagile) runServer() error {
	what.config.SetServerMode(true)
	serverError := what.config.CheckServerFolder()
	if serverError != nil {
		return serverError
	}

	server.RunServer(what.config, risks.GetBuiltInRiskRules())
	return nil
}
