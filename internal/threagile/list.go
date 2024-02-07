package threagile

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/security/risks"
	"github.com/threagile/threagile/pkg/security/types"
	"strings"
)

func (what *Threagile) initList() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.ListRiskRulesCommand,
		Short: "Print available risk rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println(docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp))
			cmd.Println("The following risk rules are available (can be extended via custom risk rules):")
			cmd.Println()
			cmd.Println("----------------------")
			cmd.Println("Custom risk rules:")
			cmd.Println("----------------------")
			customRiskRules := model.LoadCustomRiskRules(strings.Split(what.flags.customRiskRulesPluginFlag, ","), common.DefaultProgressReporter{Verbose: what.flags.verboseFlag})
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
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.ListModelMacrosCommand,
		Short: "Print model macros",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp))
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
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.ListTypesCommand,
		Short: "Print type information (enum values to be used in models)",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp))
			cmd.Println()
			cmd.Println()
			cmd.Println("The following types are available (can be extended for custom rules):")
			cmd.Println()
			for name, values := range types.GetBuiltinTypeValues() {
				cmd.Println(fmt.Sprintf("  %v: %v", name, values))
			}
		},
	})

	return what
}
