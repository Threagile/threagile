package main

import (
	"fmt"
	"github.com/threagile/threagile/pkg/script"
	"github.com/threagile/threagile/pkg/script/common"
	"github.com/threagile/threagile/pkg/security/types"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

func main() {
	riskData, riskReadError := os.ReadFile(filepath.Join("test", "risk-category.yaml"))
	if riskReadError != nil {
		fmt.Printf("error reading risk category: %v\n", riskReadError)
		return
	}

	scripts, parseError := new(script.Script).Parse(riskData)
	if parseError != nil {
		fmt.Printf("error parsing scripts: %v\n", parseError)
		return
	}

	modelData, modelReadError := os.ReadFile(filepath.Join("test", "parsed-model.yaml"))
	if modelReadError != nil {
		fmt.Printf("error reading model: %v\n", modelReadError)
		return
	}

	model := new(types.ParsedModel)
	modelUnmarshalError := yaml.Unmarshal(modelData, model)
	if modelUnmarshalError != nil {
		fmt.Printf("error parsing model: %v\n", modelUnmarshalError)
		return
	}

	categoriesModel := new(types.ParsedModel)
	riskUnmarshalError := yaml.Unmarshal(riskData, categoriesModel)
	if riskUnmarshalError != nil {
		fmt.Printf("error parsing risk category: %v\n", riskUnmarshalError)
		return
	}

	var risk types.RiskCategory
	if categoriesModel.IndividualRiskCategories != nil {
		for _, item := range categoriesModel.IndividualRiskCategories {
			risk = item
		}
	}

	for name, script := range scripts {
		scope := new(common.Scope)
		addError := scope.Init(model, &risk, script.Utils())
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
}
