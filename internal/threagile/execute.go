/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks"
)

func (what *Threagile) initExecute() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   "execute-model-macro",
		Short: "Execute model macro",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			r, err := model.ReadAndAnalyzeModel(what.config, risks.GetBuiltInRiskRules(), progressReporter)
			if err != nil {
				return fmt.Errorf("unable to read and analyze model: %w", err)
			}

			macrosId := args[0]
			err = macros.ExecuteModelMacro(r.ModelInput, what.config.GetInputFile(), r.ParsedModel, macrosId)
			if err != nil {
				return fmt.Errorf("unable to execute model macro: %w", err)
			}

			return nil
		},
	})

	return what
}
