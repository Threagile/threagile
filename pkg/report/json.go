package report

import (
	"encoding/json"
	"github.com/threagile/threagile/pkg/security/types"
	"os"
)

func WriteRisksJSON(parsedModel *types.ParsedModel, filename string) {
	/*
		remainingRisks := make([]model.Risk, 0)
		for _, category := range model.SortedRiskCategories() {
			risks := model.SortedRisksOfCategory(category)
			for _, risk := range model.ReduceToOnlyStillAtRisk(risks) {
				remainingRisks = append(remainingRisks, risk)
			}
		}
	*/
	jsonBytes, err := json.Marshal(types.AllRisks(parsedModel))
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(filename, jsonBytes, 0644)
	if err != nil {
		panic(err)
	}
}

// TODO: also a "data assets" json?

func WriteTechnicalAssetsJSON(parsedModel *types.ParsedModel, filename string) {
	jsonBytes, err := json.Marshal(parsedModel.TechnicalAssets)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(filename, jsonBytes, 0644)
	if err != nil {
		panic(err)
	}
}

func WriteStatsJSON(parsedModel *types.ParsedModel, filename string) {
	jsonBytes, err := json.Marshal(types.OverallRiskStatistics(parsedModel))
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(filename, jsonBytes, 0644)
	if err != nil {
		panic(err)
	}
}
