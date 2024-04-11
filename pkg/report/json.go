package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/threagile/threagile/pkg/security/types"
)

func WriteRisksJSON(parsedModel *types.Model, filename string) error {
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
		return fmt.Errorf("failed to marshal risks to JSON: %w", err)
	}
	err = os.WriteFile(filename, jsonBytes, 0600)
	if err != nil {
		return fmt.Errorf("failed to write risks to JSON file: %w", err)
	}
	return nil
}

// TODO: also a "data assets" json?

func WriteTechnicalAssetsJSON(parsedModel *types.Model, filename string) error {
	jsonBytes, err := json.Marshal(parsedModel.TechnicalAssets)
	if err != nil {
		return fmt.Errorf("failed to marshal technical assets to JSON: %w", err)
	}
	err = os.WriteFile(filename, jsonBytes, 0600)
	if err != nil {
		return fmt.Errorf("failed to write technical assets to JSON file: %w", err)
	}
	return nil
}

func WriteStatsJSON(parsedModel *types.Model, filename string) error {
	jsonBytes, err := json.Marshal(types.OverallRiskStatistics(parsedModel))
	if err != nil {
		return fmt.Errorf("failed to marshal stats to JSON: %w", err)
	}
	err = os.WriteFile(filename, jsonBytes, 0600)
	if err != nil {
		return fmt.Errorf("failed to write stats to JSON file: %w", err)
	}
	return nil
}
