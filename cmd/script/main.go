package main

import (
	"flag"
	"fmt"
	"github.com/goccy/go-yaml"
	"github.com/threagile/threagile/pkg/risks/script"
	"github.com/threagile/threagile/pkg/types"
	"os"
	"path/filepath"

	"strings"
)

func main() {
	var scriptFilename string
	flag.StringVar(&scriptFilename, "script", "", "script file")
	flag.Parse()

	if len(scriptFilename) == 0 {
		scriptFilename = filepath.Join("pkg", "risks", "scripts", "accidental-secret-leak.yaml")
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

	for n, risk := range generatedRisks {
		riskExplanation := risk.RiskExplanation
		ratingExplanation := risk.RatingExplanation
		risk.RiskExplanation = nil
		risk.RatingExplanation = nil

		for _, riskLine := range riskExplanation {
			fmt.Println(riskLine)
		}
		fmt.Println("")

		for _, ratingLine := range ratingExplanation {
			fmt.Println(ratingLine)
		}
		fmt.Println("")

		printedRisks, printError := yaml.Marshal(risk)
		if printError != nil {
			fmt.Printf("error printing risk #%d for %q: %v\n", n+1, newRule.Category().ID, printError)
			return
		}

		fmt.Printf("generated risk #%d for %q: \n%v\n", n+1, newRule.Category().ID, string(printedRisks))

		assets := make([]*types.TechnicalAsset, 0)
		for _, techAsset := range parsedModel.TechnicalAssets {
			if strings.EqualFold(techAsset.Id, risk.MostRelevantTechnicalAssetId) {
				assets = append(assets, techAsset)
			}
		}

		if len(assets) > 0 {
			fmt.Printf("found %d asset(s) for risk #%d %q\n", len(assets), n+1, risk.SyntheticId)
			for _, asset := range assets {
				fmt.Printf("  - %v\n", asset.Title)
			}
		} else {
			fmt.Printf("no assets found for risk #%d %q\n", n+1, risk.SyntheticId)
		}
	}
}
