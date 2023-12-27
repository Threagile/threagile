/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"github.com/threagile/threagile/pkg/run"
	"strings"
)

type progressReporter interface {
	Println(a ...any) (n int, err error)
	Fatalf(format string, v ...any)
}

func LoadCustomRiskRules(pluginFiles []string, reporter progressReporter) map[string]*CustomRisk {
	customRiskRuleList := make([]string, 0)
	customRiskRules := make(map[string]*CustomRisk)
	if len(pluginFiles) > 0 {
		_, _ = reporter.Println("Loading custom risk rules:", strings.Join(pluginFiles, ", "))

		for _, pluginFile := range pluginFiles {
			if len(pluginFile) > 0 {
				runner, loadError := new(run.Runner).Load(pluginFile)
				if loadError != nil {
					reporter.Fatalf("WARNING: Custom risk rule %q not loaded: %v\n", pluginFile, loadError)
				}

				risk := new(CustomRisk)
				runError := runner.Run(nil, &risk, "-get-info")
				if runError != nil {
					reporter.Fatalf("WARNING: Failed to get ID for custom risk rule %q: %v\n", pluginFile, runError)
				}

				risk.Runner = runner
				customRiskRules[risk.ID] = risk
				customRiskRuleList = append(customRiskRuleList, risk.ID)
				_, _ = reporter.Println("Custom risk rule loaded:", risk.ID)
			}
		}

		_, _ = reporter.Println("Loaded custom risk rules:", strings.Join(customRiskRuleList, ", "))
	}

	return customRiskRules
}
