package threagile

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/risks"
)

func (what *Threagile) initImport() *Threagile {
	analyze := &cobra.Command{
		Use:     ImportModelCommand,
		Short:   "Import model (convert to internal representation)",
		Aliases: []string{"import"},
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			commands := what.readCommands()
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			r, err := model.ReadAndAnalyzeModel(what.config, risks.GetBuiltInRiskRules(), progressReporter)
			if err != nil {
				return fmt.Errorf("failed to read and analyze model: %w", err)
			}

			err = report.Generate(what.config, r, commands, risks.GetBuiltInRiskRules(), progressReporter)
			if err != nil {
				return fmt.Errorf("failed to generate reports: %w", err)
			}

			return nil
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	what.rootCmd.AddCommand(analyze)

	return what
}
