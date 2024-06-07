package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/threagile/threagile/pkg/script"
	"github.com/threagile/threagile/pkg/types"
	"gopkg.in/yaml.v3"
)

func main() {
	var scriptFilename string
	flag.StringVar(&scriptFilename, "script", "", "script file")
	flag.Parse()

	if len(scriptFilename) == 0 {
		scriptFilename = filepath.Join("test", "risk-category.yaml")
	}

	scriptFilename = filepath.Clean(scriptFilename)
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

	generatedRisks, riskError := newRule.GenerateRisks(parsedModel)
	if riskError != nil {
		fmt.Printf("error generating risks for %q: %v\n", newRule.Category().ID, riskError)
		return
	}

	printedRisks, printError := yaml.Marshal(generatedRisks)
	if printError != nil {
		fmt.Printf("error printing risks for %q: %v\n", newRule.Category().ID, printError)
		return
	}

	fmt.Printf("generated risks for %q: \n%v\n", newRule.Category().ID, string(printedRisks))

	for _, risk := range generatedRisks {
		assets, assetsError := newRule.GetTechnicalAssetsByRiskID(parsedModel, risk.SyntheticId)
		if assetsError != nil {
			fmt.Printf("failed to get assets for risk %q: %v\n", risk.SyntheticId, assetsError)
			return
		}

		if len(assets) > 0 {
			fmt.Printf("found %d asset(s) for risk %q\n", len(assets), risk.SyntheticId)
			for _, asset := range assets {
				fmt.Printf("  - %v\n", asset.Title)
			}
		} else {
			fmt.Printf("no assets found for risk %q\n", risk.SyntheticId)
		}
	}
}
