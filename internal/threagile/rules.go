/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/security/risks"
	"github.com/threagile/threagile/pkg/security/types"
	"strings"

	"github.com/spf13/cobra"

	"github.com/threagile/threagile/pkg/docs"
)

var listRiskRules = &cobra.Command{
	Use:   "list-risk-rules",
	Short: "Print available risk rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		plugins, err := cmd.Flags().GetString("custom-risk-rules-plugin")
		if err != nil {
			cmd.Printf("Unable to read custom-risk-rules-plugin flag: %v", err)
			return err
		}

		cmd.Println(docs.Logo + "\n\n" + docs.VersionText)
		cmd.Println("The following risk rules are available (can be extended via custom risk rules):")
		cmd.Println()
		cmd.Println("----------------------")
		cmd.Println("Custom risk rules:")
		cmd.Println("----------------------")
		customRiskRules := types.LoadCustomRiskRules(strings.Split(plugins, ","), common.GetProgressReporter(cmd))
		for id, customRule := range customRiskRules {
			cmd.Println(id, "-->", customRule.Category.Title, "--> with tags:", customRule.Tags)
		}
		cmd.Println()
		cmd.Println("--------------------")
		cmd.Println("Built-in risk rules:")
		cmd.Println("--------------------")
		cmd.Println()
		for _, rule := range risks.GetBuiltInRiskRules() {
			cmd.Println(rule.Category().Id, "-->", rule.Category().Title, "--> with tags:", rule.SupportedTags())
		}

		return nil
	},
}

var explainRiskRules = &cobra.Command{
	Use:   "explain-risk-rules",
	Short: "Detailed explanation of all the risk rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		plugins, err := cmd.Flags().GetString("custom-risk-rules-plugin")
		if err != nil {
			cmd.Printf("Unable to read custom-risk-rules-plugin flag: %v", err)
			return err
		}

		cmd.Println(docs.Logo + "\n\n" + docs.VersionText)
		cmd.Println("Explanation for risk rules:")
		cmd.Println()
		cmd.Println("----------------------")
		cmd.Println("Custom risk rules:")
		cmd.Println("----------------------")
		customRiskRules := types.LoadCustomRiskRules(strings.Split(plugins, ","), common.GetProgressReporter(cmd))
		for _, customRule := range customRiskRules {
			cmd.Printf("%v: %v\n", customRule.Category.Id, customRule.Category.Description)
		}
		cmd.Println()
		cmd.Println("--------------------")
		cmd.Println("Built-in risk rules:")
		cmd.Println("--------------------")
		cmd.Println()
		for _, rule := range risks.GetBuiltInRiskRules() {
			cmd.Printf("%v: %v\n", rule.Category().Id, rule.Category().Description)
		}
		cmd.Println()

		return nil
	},
}

func init() {
	listRiskRules.PersistentFlags().String(customRiskRulesPluginFlagName, "", "custom risk rules plugin (default: none)")
	rootCmd.AddCommand(listRiskRules)

	explainRiskRules.PersistentFlags().String(customRiskRulesPluginFlagName, "", "custom risk rules plugin (default: none)")
	rootCmd.AddCommand(explainRiskRules)
}
