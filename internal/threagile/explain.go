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
	return what.initExplainNew()
}

func (what *Threagile) initExplainNew() *Threagile {
	explainCmd := &cobra.Command{
		Use:   "explain",
		Short: "Explain an item",
	}

	what.rootCmd.AddCommand(explainCmd)

	explainCmd.AddCommand(&cobra.Command{
		Use:        "risk",
		Short:      "Detailed explanation of why a risk was flagged",
		Args:       cobra.MinimumNArgs(1),
		ArgAliases: []string{"risk_id", "..."},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := what.readConfig(cmd, what.buildTimestamp)
			progressReporter := common.DefaultProgressReporter{Verbose: cfg.Verbose}

			result, runError := model.ReadAndAnalyzeModel(*cfg, progressReporter)
			if runError != nil {
				cmd.Printf("Failed to read and analyze model: %v", runError)
				return runError
			}

			cmd.Println()

			for _, risk := range args {
				cmd.Printf("risk: %v\n", risk)
				found := false

				customRiskRules := model.LoadCustomRiskRules(strings.Split(what.flags.customRiskRulesPluginFlag, ","), common.DefaultProgressReporter{Verbose: what.flags.verboseFlag})
				for _, rule := range customRiskRules {
					if rule.MatchRisk(result.ParsedModel, risk) {
						cmd.Printf("matching custom rule: %v\n", rule.Category().Id)

						explanation := rule.ExplainRisk(result.ParsedModel, risk)
						if explanation != nil {
							cmd.Printf("explanation:\n%v\n", strings.Join(explanation, "\n"))
							found = true
						}

						cmd.Println()
					}
				}

				for _, rule := range risks.GetBuiltInRiskRules() {
					if rule.MatchRisk(result.ParsedModel, risk) {
						cmd.Printf("matching built-in rule: %v\n", rule.Category().Id)

						explanation := rule.ExplainRisk(result.ParsedModel, risk)
						if explanation != nil {
							cmd.Printf("explanation:\n%v\n", strings.Join(explanation, "\n"))
							found = true
						}

						cmd.Println()
					}
				}

				if !found {
					cmd.Printf("no matching rule found to explain risk %q\n", risk)
				}
			}

			return nil
		},
	})

	explainCmd.AddCommand(&cobra.Command{
		Use:   "rules",
		Short: "Detailed explanation of all the risk rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println(docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp))
			cmd.Println("Explanation for risk rules:")
			cmd.Println()
			cmd.Println("----------------------")
			cmd.Println("Custom risk rules:")
			cmd.Println("----------------------")
			customRiskRules := model.LoadCustomRiskRules(strings.Split(what.flags.customRiskRulesPluginFlag, ","), common.DefaultProgressReporter{Verbose: what.flags.verboseFlag})
			for _, rule := range customRiskRules {
				cmd.Printf("%v: %v\n", rule.Category().Id, rule.Category().Description)
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

	explainCmd.AddCommand(&cobra.Command{
		Use:   "macros",
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
			for _, macroList := range macros.ListBuiltInMacros() {
				details := macroList.GetMacroDetails()
				cmd.Printf("%v: %v\n", details.ID, details.Title)
			}

			cmd.Println()
		},
	})

	explainCmd.AddCommand(&cobra.Command{
		Use:   "types",
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
