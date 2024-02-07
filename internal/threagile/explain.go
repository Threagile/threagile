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

func (what *Threagile) initExplain() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.ExplainRiskCommand,
		Short: "Detailed explanation of why a risk was flagged",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := what.readConfig(cmd, what.buildTimestamp)
			progressReporter := common.DefaultProgressReporter{Verbose: cfg.Verbose}

			r, runError := model.ReadAndAnalyzeModel(*cfg, progressReporter)
			if runError != nil {
				cmd.Printf("Failed to read and analyze model: %v", runError)
				return runError
			}

			for _, risk := range args {
				explainError := r.ExplainRisk(cfg, risk, progressReporter)
				if explainError != nil {
					cmd.Printf("Failed to explain risk %q: %v \n", risk, explainError)
					return explainError
				}
			}

			return nil
		},
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.ExplainRiskRulesCommand,
		Short: "Detailed explanation of all the risk rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println(docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp))
			cmd.Println("Explanation for risk rules:")
			cmd.Println()
			cmd.Println("----------------------")
			cmd.Println("Custom risk rules:")
			cmd.Println("----------------------")
			customRiskRules := model.LoadCustomRiskRules(strings.Split(what.flags.customRiskRulesPluginFlag, ","), common.DefaultProgressReporter{Verbose: what.flags.verboseFlag})
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
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.ExplainModelMacrosCommand,
		Short: "Explain model macros",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp))
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
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.ExplainTypesCommand,
		Short: "Print type information (enum values to be used in models)",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp))
			fmt.Println("Explanation for the types:")
			cmd.Println()
			cmd.Println("The following types are available (can be extended for custom rules):")
			cmd.Println()
			for name, values := range types.GetBuiltinTypeValues() {
				cmd.Println(name)
				for _, candidate := range values {
					cmd.Printf("\t %v: %v\n", candidate, candidate.Explain())
				}
			}
		},
	})

	return what
}
