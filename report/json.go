package report

import (
	"encoding/json"
	"github.com/threagile/threagile/model"
	"io/ioutil"
)

func WriteRisksJSON(filename string) {
	/*
		remainingRisks := make([]model.Risk, 0)
		for _, category := range model.SortedRiskCategories() {
			risks := model.SortedRisksOfCategory(category)
			for _, risk := range model.ReduceToOnlyStillAtRisk(risks) {
				remainingRisks = append(remainingRisks, risk)
			}
		}
	*/
	jsonBytes, err := json.Marshal(model.AllRisks())
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(filename, jsonBytes, 0644)
	if err != nil {
		panic(err)
	}
}

// TODO: also a "data assets" json?
func WriteTechnicalAssetsJSON(filename string) {
	jsonBytes, err := json.Marshal(model.ParsedModelRoot.TechnicalAssets)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(filename, jsonBytes, 0644)
	if err != nil {
		panic(err)
	}
}

func WriteStatsJSON(filename string) {
	jsonBytes, err := json.Marshal(model.OverallRiskStatistics())
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(filename, jsonBytes, 0644)
	if err != nil {
		panic(err)
	}
}
