package threagile

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
)

func (what *Threagile) initExplain() *Threagile {
	return what.initExplainNew()
}

func (what *Threagile) initExplainNew() *Threagile {
	explainCmd := &cobra.Command{
		Use:   ExplainCommand,
		Short: "Explain an item",
	}

	what.rootCmd.AddCommand(explainCmd)

	explainCmd.AddCommand(
		&cobra.Command{
			Use:        RiskItem,
			Short:      "Detailed explanation of why a risk was flagged",
			Args:       cobra.MinimumNArgs(1),
			ArgAliases: []string{"risk_id", "..."},
			RunE:       what.explainRisk,
		},
		&cobra.Command{
			Use:   RulesItem,
			Short: "Detailed explanation of all the risk rules",
			RunE:  what.explainRules,
		},
		&cobra.Command{
			Use:   MacrosItem,
			Short: "Explain model macros",
			Run:   what.explainMacros,
		},
		&cobra.Command{
			Use:   TypesItem,
			Short: "Print type information (enum values to be used in models)",
			Run:   what.explainTypes,
		})

	return what
}

func (what *Threagile) explainRisk(cmd *cobra.Command, args []string) error {
	what.processArgs(cmd, args)

	// todo: reuse model if already loaded

	result, runError := model.ReadAndAnalyzeModel(what.config, risks.GetBuiltInRiskRules())
	if runError != nil {
		cmd.Printf("Failed to read and analyze model: %v", runError)
		return runError
	}

	// todo: implement this

	_ = result
	return fmt.Errorf("not implemented yet")
}

func (what *Threagile) explainRules(cmd *cobra.Command, args []string) error {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
	cmd.Println("Explanation for risk rules:")
	cmd.Println()
	cmd.Println("----------------------")
	cmd.Println("Custom risk rules:")
	cmd.Println("----------------------")
	customRiskRules := model.LoadCustomRiskRules(what.config.GetPluginFolder(), what.config.GetRiskRulePlugins(), DefaultProgressReporter{Verbose: what.config.GetVerbose()})
	for _, rule := range customRiskRules {
		cmd.Printf("%v: %v\n", rule.Category().ID, rule.Category().Description)
	}
	cmd.Println()
	cmd.Println("--------------------")
	cmd.Println("Built-in risk rules:")
	cmd.Println("--------------------")
	cmd.Println()
	for _, rule := range risks.GetBuiltInRiskRules() {
		cmd.Printf("%v: %v\n", rule.Category().ID, rule.Category().Description)
	}
	cmd.Println()

	return nil
}

func (what *Threagile) explainMacros(cmd *cobra.Command, args []string) {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
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
}

func (what *Threagile) explainTypes(cmd *cobra.Command, args []string) {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
	fmt.Println("Explanation for the types:")
	cmd.Println()
	cmd.Println("The following types are available (can be extended for custom rules):")
	cmd.Println()
	for name, values := range types.GetBuiltinTypeValues(what.config) {
		cmd.Println(name)
		for _, candidate := range values {
			cmd.Printf("\t %v: %v\n", candidate, candidate.Explain())
		}
	}
}
