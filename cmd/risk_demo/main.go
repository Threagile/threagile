package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/security/types"
)

type customRiskRule string

// exported as symbol (here simply as variable to interface to bundle many functions under one symbol) named "RiskRule"

var CustomRiskRule customRiskRule

func main() {
	getInfo := flag.Bool("get-info", false, "get rule info")
	generateRisks := flag.Bool("generate-risks", false, "generate risks")
	flag.Parse()

	if *getInfo {
		rule := new(customRiskRule)
		category := rule.Category()
		riskData, marshalError := json.Marshal(model.CustomRisk{
			ID:       category.Id,
			Category: category,
			Tags:     rule.SupportedTags(),
		})

		if marshalError != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to print risk data: %v", marshalError)
			os.Exit(-2)
		}

		_, _ = fmt.Fprint(os.Stdout, riskData)
		os.Exit(0)
	}

	if *generateRisks {
		reader := bufio.NewReader(os.Stdin)
		inData, outError := io.ReadAll(reader)
		if outError != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to read model data from stdin\n")
			os.Exit(-2)
		}

		var input types.ParsedModel
		inError := json.Unmarshal(inData, &input)
		if inError != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to parse model: %v\n", inError)
			os.Exit(-2)
		}

		generatedRisks := new(customRiskRule).GenerateRisks(&input)
		outData, marshalError := json.Marshal(generatedRisks)
		if marshalError != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to print generated risks: %v\n", marshalError)
			os.Exit(-2)
		}

		_, _ = fmt.Fprint(os.Stdout, outData)
		os.Exit(0)
	}

	flag.Usage()
	os.Exit(-2)
}

func (r customRiskRule) Category() types.RiskCategory {
	return types.RiskCategory{
		Id:                         "demo",
		Title:                      "Just a Demo",
		Description:                "Demo Description",
		Impact:                     "Demo Impact",
		ASVS:                       "Demo ASVS",
		CheatSheet:                 "https://example.com",
		Action:                     "Demo Action",
		Mitigation:                 "Demo Mitigation",
		Check:                      "Demo Check",
		Function:                   types.Development,
		STRIDE:                     types.Tampering,
		DetectionLogic:             "Demo Detection",
		RiskAssessment:             "Demo Risk Assessment",
		FalsePositives:             "Demo False Positive.",
		ModelFailurePossibleReason: false,
		CWE:                        0,
	}
}

func (r customRiskRule) SupportedTags() []string {
	return []string{"demo tag"}
}

func (r customRiskRule) GenerateRisks(parsedModel *types.ParsedModel) []types.Risk {
	generatedRisks := make([]types.Risk, 0)
	for _, techAsset := range parsedModel.TechnicalAssets {
		generatedRisks = append(generatedRisks, createRisk(techAsset))
	}
	return generatedRisks
}

func createRisk(technicalAsset types.TechnicalAsset) types.Risk {
	risk := types.Risk{
		CategoryId:                   CustomRiskRule.Category().Id,
		Severity:                     types.CalculateSeverity(types.VeryLikely, types.MediumImpact),
		ExploitationLikelihood:       types.VeryLikely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Demo</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
