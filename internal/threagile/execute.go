/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/model"
)

func (what *Threagile) initExecute() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   "execute-model-macro",
		Short: "Execute model macro",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := what.readConfig(cmd, what.buildTimestamp)
			progressReporter := common.DefaultProgressReporter{Verbose: cfg.Verbose}

			r, err := model.ReadAndAnalyzeModel(*cfg, progressReporter)
			if err != nil {
				return fmt.Errorf("unable to read and analyze model: %v", err)
			}

			macrosId := args[0]
			err = macros.ExecuteModelMacro(r.ModelInput, cfg.InputFile, r.ParsedModel, macrosId)
			if err != nil {
				return fmt.Errorf("unable to execute model macro: %v", err)
			}
			return nil
		},
	})

	return what
}
