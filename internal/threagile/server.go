package threagile

import (
	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/server"
)

func (what *Threagile) initServer() *Threagile {
	defaultConfig := new(Config).Defaults(what.buildTimestamp)

	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Run server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := what.readConfig(cmd, what.buildTimestamp)
			cfg.SetServerMode(true)
			serverError := cfg.CheckServerFolder()
			if serverError != nil {
				return serverError
			}
			server.RunServer(cfg, risks.GetBuiltInRiskRules())
			return nil
		},
	}

	serverCmd.PersistentFlags().IntVar(&what.flags.serverPortFlag, serverPortFlagName, defaultConfig.ServerPort(), "server port")
	serverCmd.PersistentFlags().StringVar(&what.flags.serverDirFlag, serverDirFlagName, defaultConfig.DataFolder(), "base folder for server mode (default: "+DataDir+")")

	what.rootCmd.AddCommand(serverCmd)

	return what
}
