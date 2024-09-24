package report

import (
	"sort"

	"github.com/threagile/threagile/pkg/types"
)

func filteredByRiskStatus(parsedModel *types.Model, status types.RiskStatus) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategoryWithCurrentStatus() {
		for _, risk := range risks {
			if risk.RiskStatus == status {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func filteredByRiskFunction(parsedModel *types.Model, function types.RiskFunction) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for categoryId, risks := range parsedModel.GeneratedRisksByCategory {
		category := parsedModel.GetRiskCategory(categoryId)
		for _, risk := range risks {
			if category.Function == function {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func reduceToRiskStatus(risks []*types.Risk, status types.RiskStatus) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, risk := range risks {
		if risk.RiskStatus == status {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func reduceToFunctionRisk(parsedModel *types.Model, risksByCategory map[string][]*types.Risk, function types.RiskFunction) map[string][]*types.Risk {
	result := make(map[string][]*types.Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := parsedModel.GetRiskCategory(categoryId)
			if category.Function == function {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func reduceToSTRIDERisk(parsedModel *types.Model, risksByCategory map[string][]*types.Risk, stride types.STRIDE) map[string][]*types.Risk {
	result := make(map[string][]*types.Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := parsedModel.GetRiskCategory(categoryId)
			if category != nil && category.STRIDE == stride {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func countRisks(risksByCategory map[string][]*types.Risk) int {
	result := 0
	for _, risks := range risksByCategory {
		result += len(risks)
	}
	return result
}

func totalRiskCount(parsedModel *types.Model) int {
	count := 0
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		count += len(risks)
	}
	return count
}

func sortedTechnicalAssetsByRAAAndTitle(parsedModel *types.Model) []*types.TechnicalAsset {
	assets := make([]*types.TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		assets = append(assets, asset)
	}
	sort.Sort(types.ByTechnicalAssetRAAAndTitleSort(assets))
	return assets
}

func sortedKeysOfQuestions(parsedModel *types.Model) []string {
	keys := make([]string, 0)
	for k := range parsedModel.Questions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func filteredBySeverity(parsedModel *types.Model, severity types.RiskSeverity) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategoryWithCurrentStatus() {
		for _, risk := range risks {
			if risk.Severity == severity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel *types.Model) []*types.TechnicalAsset {
	assets := make([]*types.TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		assets = append(assets, asset)
	}
	sortByTechnicalAssetRiskSeverityAndTitleStillAtRisk(assets, parsedModel)
	return assets
}

func filteredByStillAtRisk(parsedModel *types.Model) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategoryWithCurrentStatus() {
		stillAtRisk := types.ReduceToOnlyStillAtRisk(risks)
		filteredRisks = append(filteredRisks, stillAtRisk...)
	}
	return filteredRisks
}

func identifiedDataBreachProbabilityStillAtRisk(parsedModel *types.Model, dataAsset *types.DataAsset) types.DataBreachProbability {
	highestProbability := types.Improbable
	for _, risk := range filteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, dataAsset.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
		}
	}
	return highestProbability
}
