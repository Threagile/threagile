package main

import (
	"fmt"
	"github.com/threagile/threagile/pkg/script"
	"github.com/threagile/threagile/pkg/security/risks"
	"github.com/threagile/threagile/pkg/security/types"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

func main() {
	rules, loadError := risks.GetScriptRiskRules()
	if loadError != nil {
		fmt.Printf("error loading risk rules: %v\n", loadError)
		return
	}

	_ = rules

	scriptFilename := filepath.Clean(filepath.Join("test", "risk-category.yaml"))
	ruleData, ruleReadError := os.ReadFile(scriptFilename)
	if ruleReadError != nil {
		fmt.Printf("error reading risk category: %v\n", ruleReadError)
		return
	}

	newRule, parseError := new(script.RiskRule).ParseFromData(ruleData)
	if parseError != nil {
		fmt.Printf("error parsing scripts from %q: %v\n", scriptFilename, parseError)
		return
	}

	modelFilename := filepath.Clean(filepath.Join("test", "parsed-model.yaml"))
	modelData, modelReadError := os.ReadFile(modelFilename)
	if modelReadError != nil {
		fmt.Printf("error reading model: %v\n", modelReadError)
		return
	}

	parsedModel := new(types.Model)
	modelUnmarshalError := yaml.Unmarshal(modelData, parsedModel)
	if modelUnmarshalError != nil {
		fmt.Printf("error parsing model from %q: %v\n", modelFilename, modelUnmarshalError)
		return
	}

	risks, riskError := newRule.GenerateRisks(parsedModel)
	if riskError != nil {
		fmt.Printf("error generating risks for %q: %v\n", newRule.Category().ID, riskError)
		return
	}

	printedRisks, printError := yaml.Marshal(risks)
	if printError != nil {
		fmt.Printf("error printing risks for %q: %v\n", newRule.Category().ID, printError)
		return
	}

	fmt.Printf("generated risks for %q: \n%v\n", newRule.Category().ID, string(printedRisks))
}
