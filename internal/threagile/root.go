/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package threagile

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/threagile/threagile/pkg/docs"
)

var rootCmd = &cobra.Command{
	Use:   "threagile",
	Short: "\n" + docs.Logo,
	Long:  "\n" + docs.Logo + "\n\n" + docs.VersionText + "\n\n" + docs.Examples,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(listMacrosCmd)
	rootCmd.AddCommand(explainMacrosCmd)
	rootCmd.AddCommand(listTypesCmd)
	rootCmd.AddCommand(explainTypesCmd)
	rootCmd.AddCommand(listRiskRules)
	rootCmd.AddCommand(explainRiskRules)
}
