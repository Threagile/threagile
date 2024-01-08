/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"strings"

	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/security/risks"

	"github.com/spf13/cobra"

	"github.com/threagile/threagile/pkg/docs"
)

var listRiskRules = &cobra.Command{
	Use:   "list-risk-rules",
	Short: "Print available risk rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Println(docs.Logo + "\n\n" + docs.VersionText)
		cmd.Println("The following risk rules are available (can be extended via custom risk rules):")
		cmd.Println()
		cmd.Println("----------------------")
		cmd.Println("Custom risk rules:")
		cmd.Println("----------------------")
		customRiskRules := model.LoadCustomRiskRules(strings.Split(*customRiskRulesPluginFlag, ","), common.DefaultProgressReporter{Verbose: *verboseFlag})
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
		cmd.Println(docs.Logo + "\n\n" + docs.VersionText)
		cmd.Println("Explanation for risk rules:")
		cmd.Println()
		cmd.Println("----------------------")
		cmd.Println("Custom risk rules:")
		cmd.Println("----------------------")
		customRiskRules := model.LoadCustomRiskRules(strings.Split(*customRiskRulesPluginFlag, ","), common.DefaultProgressReporter{Verbose: *verboseFlag})
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
	rootCmd.AddCommand(listRiskRules)
	rootCmd.AddCommand(explainRiskRules)
}
