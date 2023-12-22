package report

import (
	"encoding/json"
	"os"

	"github.com/threagile/threagile/pkg/model"
)

func WriteRisksJSON(parsedModel *model.ParsedModel, filename string) {
	/*
		remainingRisks := make([]model.Risk, 0)
		for _, category := range model.SortedRiskCategories() {
			risks := model.SortedRisksOfCategory(category)
			for _, risk := range model.ReduceToOnlyStillAtRisk(risks) {
				remainingRisks = append(remainingRisks, risk)
			}
		}
	*/
	jsonBytes, err := json.Marshal(model.AllRisks(parsedModel))
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(filename, jsonBytes, 0644)
	if err != nil {
		panic(err)
	}
}

// TODO: also a "data assets" json?

func WriteTechnicalAssetsJSON(parsedModel *model.ParsedModel, filename string) {
	jsonBytes, err := json.Marshal(parsedModel.TechnicalAssets)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(filename, jsonBytes, 0644)
	if err != nil {
		panic(err)
	}
}

func WriteStatsJSON(parsedModel *model.ParsedModel, filename string) {
	jsonBytes, err := json.Marshal(model.OverallRiskStatistics(parsedModel))
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(filename, jsonBytes, 0644)
	if err != nil {
		panic(err)
	}
}
