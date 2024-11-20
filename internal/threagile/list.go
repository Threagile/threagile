package threagile

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
)

func (what *Threagile) initList() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   ListRiskRulesCommand,
		Short: "Print available risk rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
			cmd.Println("The following risk rules are available (can be extended via custom risk rules):")
			cmd.Println()
			cmd.Println("----------------------")
			cmd.Println("Custom risk rules:")
			cmd.Println("----------------------")
			customRiskRules := model.LoadCustomRiskRules(what.config.GetPluginFolder(), what.config.GetRiskRulePlugins(), DefaultProgressReporter{Verbose: what.config.GetVerbose()})
			for id, customRule := range customRiskRules {
				cmd.Println(id, "-->", customRule.Category().Title, "--> with tags:", customRule.SupportedTags())
			}
			cmd.Println()
			cmd.Println("--------------------")
			cmd.Println("Built-in risk rules:")
			cmd.Println("--------------------")
			cmd.Println()
			for _, rule := range risks.GetBuiltInRiskRules() {
				cmd.Println(rule.Category().ID, "-->", rule.Category().Title, "--> with tags:", rule.SupportedTags())
			}

			return nil
		},
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   ListModelMacrosCommand,
		Short: "Print model macros",
		Run: func(cmd *cobra.Command, args []string) {
			what.processArgs(cmd, args)

			cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
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
			for _, macroList := range macros.ListBuiltInMacros() {
				details := macroList.GetMacroDetails()
				cmd.Println(details.ID, "-->", details.Title)
			}
			cmd.Println()
		},
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   ListTypesCommand,
		Short: "Print type information (enum values to be used in models)",
		Run: func(cmd *cobra.Command, args []string) {
			what.processArgs(cmd, args)

			cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
			cmd.Println()
			cmd.Println()
			cmd.Println("The following types are available (can be extended for custom rules):")
			cmd.Println()
			for name, values := range types.GetBuiltinTypeValues(what.config) {
				cmd.Println(fmt.Sprintf("  %v: %v", name, values))
			}
		},
	})

	return what
}
