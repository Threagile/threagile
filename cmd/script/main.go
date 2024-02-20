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

const (
	textRisk = `
    risk:
      parameter: tech_asset
      id: "{$risk.id}@{tech_asset.id}"
      title: "get_title({tech_asset})"
      severity: "calculate_severity(unlikely, get_impact({tech_asset}))"
      exploitation_likelihood: unlikely
      exploitation_impact: "get_impact({tech_asset})"
      data_breach_probability: probable
      data_breach_technical_assets:
        - "{tech_asset.id}"
      most_relevant_data_asset: "{tech_asset.id}"
`
	textMatch = `
    match:
      parameter: tech_asset
      do:
        if:
          and:
            - false: "{tech_asset.out_of_scope}"
            - contains:
                item: "{tech_asset.technology}"
                in:
                  - sourcecode-repository
                  - artifact-registry
          then:
            return: true
`
	textUtils = `
    utils:
      get_title:
        parameters:
          - tech_asset
        do:
          - if:
              contains:
                item: git
                in: "{tech_asset.tags}"
              then:
                - return:
                    "<b>Accidental Secret Leak(Git)</b> risk at <b>{tech_asset.title}</b>: <u>Git Leak Prevention</u>"
              else:
                - return:
                    "<b>Accidental Secret Leak</b> risk at <b>{tech_asset.title}"

      get_impact:
        parameters:
          - tech_asset
        do:
          - assign:
              - impact: low
              - highest_confidentiality: "get_highest({tech_asset}, confidentiality)"
              - highest_integrity: "get_highest({tech_asset}, integrity)"
              - highest_availability: "get_highest({tech_asset}, availability)"
          - if:
              or:
                - equal-or-greater:
                    as: confidentiality
                    first: "{highest_confidentiality}"
                    second: confidential
                - equal-or-greater:
                    as: integrity
                    first: "{highest_integrity}"
                    second: critical
                - equal-or-greater:
                    as: availability
                    first: "{highest_availability}"
                    second: critical
              then:
                - assign:
                    impact: medium
          - if:
              or:
                - equal-or-greater:
                    as: confidentiality
                    first: "{highest_confidentiality}"
                    second: strictly-confidential
                - equal-or-greater:
                    as: integrity
                    first: "{highest_integrity}"
                    second: mission-critical
                - equal-or-greater:
                    as: availability
                    first: "{highest_availability}"
                    second: mission-critical
              then:
                - assign:
                    impact: high
          - return: "{impact}"

      get_highest:
        parameters:
          - tech_asset
          - "type"
        do:
          - assign:
              - value: "{tech_asset.{type}}"
          - loop:
              in: "{tech_asset.data_assets_processed}"
              item: data_id
              do:
                if:
                  greater:
                    first: "{$model.data_assets.{data_id}.{type}}"
                    second: "{value}"
                  then:
                    - assign:
                        value: "{$model.data_assets.{data_id}.{type}}"
          - return: "{value}"
`
	textAll = textRisk + textMatch + textUtils
)

func main() {
	n := 4
	text := ""
	switch n {
	case 1:
		text = textRisk
	case 2:
		text = textMatch
	case 3:
		text = textUtils
	case 4:
		text = textAll
	}

	testScript := new(script.Script)
	parseError := testScript.Parse([]byte(text))
	if parseError != nil {
		fmt.Printf("error parsing script: %v\n", parseError)
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

	riskData, riskReadError := os.ReadFile(filepath.Join("test", "risk-category.yaml"))
	if riskReadError != nil {
		fmt.Printf("error reading risk category: %v\n", riskReadError)
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

	scope := new(common.Scope)
	addError := scope.Init(model, &risk, testScript.Utils())
	if addError != nil {
		fmt.Printf("error adding model to scope: %v\n", addError)
		return
	}

	risks, errorLiteral, riskError := testScript.GenerateRisks(scope)
	if riskError != nil {
		fmt.Printf("error generating risks: %v\n", riskError)

		if len(errorLiteral) > 0 {
			fmt.Printf("in:\n%v\n", testScript.IndentPrintf(1, errorLiteral))
		}

		return
	}

	printedRisks, printError := yaml.Marshal(risks)
	if printError != nil {
		fmt.Printf("error printing risks: %v\n", printError)
		return
	}

	fmt.Printf("generated risks: \n%v\n", string(printedRisks))
}
