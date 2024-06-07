/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"sort"
	"strings"
)

func GetRiskCategory(parsedModel *Model, categoryID string) *RiskCategory {
	if len(parsedModel.CustomRiskCategories) > 0 {
		for _, custom := range parsedModel.CustomRiskCategories {
			if strings.EqualFold(custom.ID, categoryID) {
				return custom
			}
		}
	}

	if len(parsedModel.BuiltInRiskCategories) > 0 {
		for _, builtIn := range parsedModel.BuiltInRiskCategories {
			if strings.EqualFold(builtIn.ID, categoryID) {
				return builtIn
			}
		}
	}

	return nil
}

func AllRisks(parsedModel *Model) []*Risk {
	result := make([]*Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		result = append(result, risks...)
	}
	return result
}

func ReduceToOnlyStillAtRisk(risks []*Risk) []*Risk {
	filteredRisks := make([]*Risk, 0)
	for _, risk := range risks {
		if risk.RiskStatus.IsStillAtRisk() {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func HighestSeverityStillAtRisk(model *Model, risks []*Risk) RiskSeverity {
	result := LowSeverity
	for _, risk := range risks {
		if risk.Severity > result && risk.RiskStatus.IsStillAtRisk() {
			result = risk.Severity
		}
	}
	return result
}

type ByRiskCategoryTitleSort []*RiskCategory

func (what ByRiskCategoryTitleSort) Len() int { return len(what) }
func (what ByRiskCategoryTitleSort) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByRiskCategoryTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

func SortByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk(parsedModel *Model, riskCategories []*RiskCategory) {
	sort.Slice(riskCategories, func(i, j int) bool {
		risksLeft := ReduceToOnlyStillAtRisk(parsedModel.GeneratedRisksByCategory[riskCategories[i].ID])
		risksRight := ReduceToOnlyStillAtRisk(parsedModel.GeneratedRisksByCategory[riskCategories[j].ID])
		highestLeft := HighestSeverityStillAtRisk(parsedModel, risksLeft)
		highestRight := HighestSeverityStillAtRisk(parsedModel, risksRight)
		if highestLeft == highestRight {
			if len(risksLeft) == 0 && len(risksRight) > 0 {
				return false
			}
			if len(risksLeft) > 0 && len(risksRight) == 0 {
				return true
			}
			return riskCategories[i].Title < riskCategories[j].Title
		}
		return highestLeft > highestRight
	})
}

type RiskStatistics struct {
	// TODO add also some more like before / after (i.e. with mitigation applied)
	Risks map[string]map[string]int `yaml:"risks" json:"risks"`
}

func SortByRiskSeverity(risks []*Risk, parsedModel *Model) {
	sort.Slice(risks, func(i, j int) bool {
		if risks[i].Severity == risks[j].Severity {
			trackingStatusLeft := risks[i].RiskStatus
			trackingStatusRight := risks[j].RiskStatus
			if trackingStatusLeft == trackingStatusRight {
				impactLeft := risks[i].ExploitationImpact
				impactRight := risks[j].ExploitationImpact
				if impactLeft == impactRight {
					likelihoodLeft := risks[i].ExploitationLikelihood
					likelihoodRight := risks[j].ExploitationLikelihood
					if likelihoodLeft == likelihoodRight {
						return risks[i].Title < risks[j].Title
					} else {
						return likelihoodLeft > likelihoodRight
					}
				} else {
					return impactLeft > impactRight
				}
			} else {
				return trackingStatusLeft < trackingStatusRight
			}
		}
		return risks[i].Severity > risks[j].Severity

	})
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

func SortedRiskCategories(parsedModel *Model) []*RiskCategory {
	categoryMap := make(map[string]*RiskCategory)
	for categoryId := range parsedModel.GeneratedRisksByCategory {
		category := GetRiskCategory(parsedModel, categoryId)
		if category != nil {
			categoryMap[categoryId] = category
		}
	}

	categories := make([]*RiskCategory, 0)
	for categoryId := range categoryMap {
		categories = append(categories, categoryMap[categoryId])
	}

	SortByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk(parsedModel, categories)
	return categories
}

func SortedRisksOfCategory(parsedModel *Model, category *RiskCategory) []*Risk {
	risks := parsedModel.GeneratedRisksByCategory[category.ID]
	SortByRiskSeverity(risks, parsedModel)
	return risks
}
