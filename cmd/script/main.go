package main

import (
	"fmt"
	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/script"
	"github.com/threagile/threagile/pkg/security/risks"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

func main() {
	ruleData, ruleReadError := os.ReadFile(filepath.Join("test", "risk-category.yaml"))
	if ruleReadError != nil {
		fmt.Printf("error reading risk category: %v\n", ruleReadError)
		return
	}

	scripts, parseError := new(script.Script).ParseScripts(ruleData)
	if parseError != nil {
		fmt.Printf("error parsing scripts: %v\n", parseError)
		return
	}

	modelData, modelReadError := os.ReadFile(filepath.Join("test", "parsed-model.yaml"))
	if modelReadError != nil {
		fmt.Printf("error reading model: %v\n", modelReadError)
		return
	}

	inputModel := new(input.Model)
	modelUnmarshalError := yaml.Unmarshal(modelData, inputModel)
	if modelUnmarshalError != nil {
		fmt.Printf("error parsing model: %v\n", modelUnmarshalError)
		return
	}

	/*
		categoriesModel := new(input.Model)
		riskUnmarshalError := yaml.Unmarshal(riskData, categoriesModel)
		if riskUnmarshalError != nil {
			fmt.Printf("error parsing risk category: %v\n", riskUnmarshalError)
			return
		}
	*/

	parsedModel, modelError := model.ParseModel(&common.Config{}, inputModel, make(risks.RiskRules), make(risks.RiskRules))
	if modelError != nil {
		fmt.Printf("error importing model: %v\n", modelError)
		return
	}

	_ = parsedModel
	_ = scripts
	/*
		var risk types.RiskCategory
		if categoriesModel.CustomRiskCategories != nil {
			for _, item := range categoriesModel.CustomRiskCategories {
				risk = item
			}
		}

		if len(categoriesModel.CustomRiskCategories) == 0 {
			fmt.Printf("no risk categories\n")
			return
		}

		for name, script := range scripts {
			scope := new(script.Scope)
			addError := scope.Init(parsedModel, &risk, script.Utils())
			if addError != nil {
				fmt.Printf("error adding model to scope for %q: %v\n", name, addError)
				return
			}

			risks, errorLiteral, riskError := script.GenerateRisks(scope)
			if riskError != nil {
				fmt.Printf("error generating risks for %q: %v\n", name, riskError)

				if len(errorLiteral) > 0 {
					fmt.Printf("in:\n%v\n", script.IndentPrintf(1, errorLiteral))
				}

				return
			}

			printedRisks, printError := yaml.Marshal(risks)
			if printError != nil {
				fmt.Printf("error printing risks for %q: %v\n", name, printError)
				return
			}

			fmt.Printf("generated risks for %q: \n%v\n", name, string(printedRisks))
		}

	*/
}
