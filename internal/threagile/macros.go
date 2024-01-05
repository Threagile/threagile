/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package threagile

import (
	"github.com/spf13/cobra"

	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/macros"
)

var listMacrosCmd = &cobra.Command{
	Use:   "list-model-macros",
	Short: "Print model macros",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println(docs.Logo + "\n\n" + docs.VersionText)
		cmd.Println("The following model macros are available (can be extended via custom model macros):")
		cmd.Println()
		/* TODO finish plugin stuff
		cmd.Println("Custom model macros:")
		for _, macros := range macros.ListCustomMacros() {
			details := macros.GetMacroDetails()
			cmd.Println(details.ID, "-->", details.Title)
		}
		cmd.Println()
		*/
		cmd.Println("----------------------")
		cmd.Println("Built-in model macros:")
		cmd.Println("----------------------")
		for _, macros := range macros.ListBuiltInMacros() {
			details := macros.GetMacroDetails()
			cmd.Println(details.ID, "-->", details.Title)
		}
		cmd.Println()
	},
}

var explainMacrosCmd = &cobra.Command{
	Use:   "explain-model-macros",
	Short: "Explain model macros",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println(docs.Logo + "\n\n" + docs.VersionText)
		cmd.Println("Explanation for the model macros:")
		cmd.Println()
		/* TODO finish plugin stuff
		cmd.Println("Custom model macros:")
		for _, macros := range macros.ListCustomMacros() {
			details := macros.GetMacroDetails()
			cmd.Println(details.ID, "-->", details.Title)
		}
		cmd.Println()
		*/
		cmd.Println("----------------------")
		cmd.Println("Built-in model macros:")
		cmd.Println("----------------------")
		for _, macros := range macros.ListBuiltInMacros() {
			details := macros.GetMacroDetails()
			cmd.Printf("%v: %v\n", details.ID, details.Title)
		}

		cmd.Println()
	},
}

func init() {
	rootCmd.AddCommand(listMacrosCmd)
	rootCmd.AddCommand(explainMacrosCmd)
}
