/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"sort"
)

func GetRiskCategory(parsedModel *ParsedModel, categoryID string) *RiskCategory {
	if len(parsedModel.IndividualRiskCategories) > 0 {
		custom, customOk := parsedModel.IndividualRiskCategories[categoryID]
		if customOk {
			return &custom
		}
	}

	if len(parsedModel.BuiltInRiskCategories) > 0 {
		builtIn, builtInOk := parsedModel.BuiltInRiskCategories[categoryID]
		if builtInOk {
			return &builtIn
		}
	}

	return nil
}

func GetRiskCategories(parsedModel *ParsedModel, categoryIDs []string) []RiskCategory {
	categoryMap := make(map[string]RiskCategory)
	for _, categoryId := range categoryIDs {
		category := GetRiskCategory(parsedModel, categoryId)
		if category != nil {
			categoryMap[categoryId] = *category
		}
	}

	categories := make([]RiskCategory, 0)
	for categoryId := range categoryMap {
		categories = append(categories, categoryMap[categoryId])
	}

	return categories
}

func AllRisks(parsedModel *ParsedModel) []Risk {
	result := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		result = append(result, risks...)
	}
	return result
}

func ReduceToOnlyStillAtRisk(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func HighestExploitationLikelihood(risks []Risk) RiskExploitationLikelihood {
	result := Unlikely
	for _, risk := range risks {
		if risk.ExploitationLikelihood > result {
			result = risk.ExploitationLikelihood
		}
	}
	return result
}

func HighestExploitationImpact(risks []Risk) RiskExploitationImpact {
	result := LowImpact
	for _, risk := range risks {
		if risk.ExploitationImpact > result {
			result = risk.ExploitationImpact
		}
	}
	return result
}

func HighestSeverityStillAtRisk(model *ParsedModel, risks []Risk) RiskSeverity {
	result := LowSeverity
	for _, risk := range risks {
		if risk.Severity > result && risk.GetRiskTrackingStatusDefaultingUnchecked(model).IsStillAtRisk() {
			result = risk.Severity
		}
	}
	return result
}

type ByRiskCategoryTitleSort []RiskCategory

func (what ByRiskCategoryTitleSort) Len() int { return len(what) }
func (what ByRiskCategoryTitleSort) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByRiskCategoryTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

func SortByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk(parsedModel *ParsedModel, riskCategories []RiskCategory) {
	sort.Slice(riskCategories, func(i, j int) bool {
		risksLeft := ReduceToOnlyStillAtRisk(parsedModel, parsedModel.GeneratedRisksByCategory[riskCategories[i].Id])
		risksRight := ReduceToOnlyStillAtRisk(parsedModel, parsedModel.GeneratedRisksByCategory[riskCategories[j].Id])
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

func SortByRiskSeverity(risks []Risk, parsedModel *ParsedModel) {
	sort.Slice(risks, func(i, j int) bool {
		if risks[i].Severity == risks[j].Severity {
			trackingStatusLeft := risks[i].GetRiskTrackingStatusDefaultingUnchecked(parsedModel)
			trackingStatusRight := risks[j].GetRiskTrackingStatusDefaultingUnchecked(parsedModel)
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

func SortByDataBreachProbability(risks []Risk, parsedModel *ParsedModel) {
	sort.Slice(risks, func(i, j int) bool {

		if risks[i].DataBreachProbability == risks[j].DataBreachProbability {
			trackingStatusLeft := risks[i].GetRiskTrackingStatusDefaultingUnchecked(parsedModel)
			trackingStatusRight := risks[j].GetRiskTrackingStatusDefaultingUnchecked(parsedModel)
			if trackingStatusLeft == trackingStatusRight {
				return risks[i].Title < risks[j].Title
			} else {
				return trackingStatusLeft < trackingStatusRight
			}
		}
		return risks[i].DataBreachProbability > risks[j].DataBreachProbability
	})
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

func SortedRiskCategories(parsedModel *ParsedModel) []RiskCategory {
	categoryMap := make(map[string]RiskCategory)
	for categoryId := range parsedModel.GeneratedRisksByCategory {
		category := GetRiskCategory(parsedModel, categoryId)
		if category != nil {
			categoryMap[categoryId] = *category
		}
	}

	categories := make([]RiskCategory, 0)
	for categoryId := range categoryMap {
		categories = append(categories, categoryMap[categoryId])
	}

	SortByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk(parsedModel, categories)
	return categories
}

func SortedRisksOfCategory(parsedModel *ParsedModel, category RiskCategory) []Risk {
	risks := parsedModel.GeneratedRisksByCategory[category.Id]
	SortByRiskSeverity(risks, parsedModel)
	return risks
}

func CountRisks(risksByCategory map[string][]Risk) int {
	result := 0
	for _, risks := range risksByCategory {
		result += len(risks)
	}
	return result
}

func RisksOfOnlySTRIDESpoofing(parsedModel *ParsedModel, risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category != nil {
				if category.STRIDE == Spoofing {
					result[categoryId] = append(result[categoryId], risk)
				}
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDETampering(parsedModel *ParsedModel, risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category != nil {
				if category.STRIDE == Tampering {
					result[categoryId] = append(result[categoryId], risk)
				}
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDERepudiation(parsedModel *ParsedModel, risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.STRIDE == Repudiation {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDEInformationDisclosure(parsedModel *ParsedModel, risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.STRIDE == InformationDisclosure {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDEDenialOfService(parsedModel *ParsedModel, risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.STRIDE == DenialOfService {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDEElevationOfPrivilege(parsedModel *ParsedModel, risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.STRIDE == ElevationOfPrivilege {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyBusinessSide(parsedModel *ParsedModel, risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.Function == BusinessSide {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyArchitecture(parsedModel *ParsedModel, risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.Function == Architecture {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyDevelopment(parsedModel *ParsedModel, risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.Function == Development {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyOperation(parsedModel *ParsedModel, risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.Function == Operations {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func CategoriesOfOnlyRisksStillAtRisk(parsedModel *ParsedModel, risksByCategory map[string][]Risk) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			if !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				continue
			}
			categories[categoryId] = struct{}{}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyCriticalRisks(parsedModel *ParsedModel, risksByCategory map[string][]Risk, initialRisks bool) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				continue
			}
			if risk.Severity == CriticalSeverity {
				categories[categoryId] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyHighRisks(parsedModel *ParsedModel, risksByCategory map[string][]Risk, initialRisks bool) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(parsedModel.GeneratedRisksByCategory[categoryId])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(parsedModel, parsedModel.GeneratedRisksByCategory[categoryId])
			}
			if risk.Severity == HighSeverity && highest < CriticalSeverity {
				categories[categoryId] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyElevatedRisks(parsedModel *ParsedModel, risksByCategory map[string][]Risk, initialRisks bool) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(parsedModel.GeneratedRisksByCategory[categoryId])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(parsedModel, parsedModel.GeneratedRisksByCategory[categoryId])
			}
			if risk.Severity == ElevatedSeverity && highest < HighSeverity {
				categories[categoryId] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyMediumRisks(parsedModel *ParsedModel, risksByCategory map[string][]Risk, initialRisks bool) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(parsedModel.GeneratedRisksByCategory[categoryId])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(parsedModel, parsedModel.GeneratedRisksByCategory[categoryId])
			}
			if risk.Severity == MediumSeverity && highest < ElevatedSeverity {
				categories[categoryId] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyLowRisks(parsedModel *ParsedModel, risksByCategory map[string][]Risk, initialRisks bool) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(parsedModel.GeneratedRisksByCategory[categoryId])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(parsedModel, parsedModel.GeneratedRisksByCategory[categoryId])
			}
			if risk.Severity == LowSeverity && highest < MediumSeverity {
				categories[categoryId] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func HighestSeverity(risks []Risk) RiskSeverity {
	result := LowSeverity
	for _, risk := range risks {
		if risk.Severity > result {
			result = risk.Severity
		}
	}
	return result
}

func keysAsSlice(categories map[string]struct{}) []string {
	result := make([]string, 0, len(categories))
	for k := range categories {
		result = append(result, k)
	}
	return result
}

func FilteredByOnlyBusinessSide(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for categoryId, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.Function == BusinessSide {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyArchitecture(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for categoryId, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.Function == Architecture {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyDevelopment(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for categoryId, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.Function == Development {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyOperation(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for categoryId, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.Function == Operations {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyCriticalRisks(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == CriticalSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyHighRisks(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == HighSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyElevatedRisks(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == ElevatedSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyMediumRisks(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == MediumSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyLowRisks(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Severity == LowSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilterByModelFailures(parsedModel *ParsedModel, risksByCat map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, risks := range risksByCat {
		category := GetRiskCategory(parsedModel, categoryId)
		if category.ModelFailurePossibleReason {
			result[categoryId] = risks
		}
	}

	return result
}

func FlattenRiskSlice(risksByCat map[string][]Risk) []Risk {
	result := make([]Risk, 0)
	for _, risks := range risksByCat {
		result = append(result, risks...)
	}
	return result
}

func TotalRiskCount(parsedModel *ParsedModel) int {
	count := 0
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		count += len(risks)
	}
	return count
}

func FilteredByRiskTrackingUnchecked(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == Unchecked {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingInDiscussion(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == InDiscussion {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingAccepted(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == Accepted {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingInProgress(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == InProgress {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingMitigated(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == Mitigated {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByRiskTrackingFalsePositive(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == FalsePositive {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func ReduceToOnlyHighRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.Severity == HighSeverity {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyMediumRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.Severity == MediumSeverity {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyLowRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.Severity == LowSeverity {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingUnchecked(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == Unchecked {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingInDiscussion(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == InDiscussion {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingAccepted(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == Accepted {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingInProgress(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == InProgress {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingMitigated(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == Mitigated {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingFalsePositive(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == FalsePositive {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func FilteredByStillAtRisk(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func OverallRiskStatistics(parsedModel *ParsedModel) RiskStatistics {
	result := RiskStatistics{}
	result.Risks = make(map[string]map[string]int)
	result.Risks[CriticalSeverity.String()] = make(map[string]int)
	result.Risks[CriticalSeverity.String()][Unchecked.String()] = 0
	result.Risks[CriticalSeverity.String()][InDiscussion.String()] = 0
	result.Risks[CriticalSeverity.String()][Accepted.String()] = 0
	result.Risks[CriticalSeverity.String()][InProgress.String()] = 0
	result.Risks[CriticalSeverity.String()][Mitigated.String()] = 0
	result.Risks[CriticalSeverity.String()][FalsePositive.String()] = 0
	result.Risks[HighSeverity.String()] = make(map[string]int)
	result.Risks[HighSeverity.String()][Unchecked.String()] = 0
	result.Risks[HighSeverity.String()][InDiscussion.String()] = 0
	result.Risks[HighSeverity.String()][Accepted.String()] = 0
	result.Risks[HighSeverity.String()][InProgress.String()] = 0
	result.Risks[HighSeverity.String()][Mitigated.String()] = 0
	result.Risks[HighSeverity.String()][FalsePositive.String()] = 0
	result.Risks[ElevatedSeverity.String()] = make(map[string]int)
	result.Risks[ElevatedSeverity.String()][Unchecked.String()] = 0
	result.Risks[ElevatedSeverity.String()][InDiscussion.String()] = 0
	result.Risks[ElevatedSeverity.String()][Accepted.String()] = 0
	result.Risks[ElevatedSeverity.String()][InProgress.String()] = 0
	result.Risks[ElevatedSeverity.String()][Mitigated.String()] = 0
	result.Risks[ElevatedSeverity.String()][FalsePositive.String()] = 0
	result.Risks[MediumSeverity.String()] = make(map[string]int)
	result.Risks[MediumSeverity.String()][Unchecked.String()] = 0
	result.Risks[MediumSeverity.String()][InDiscussion.String()] = 0
	result.Risks[MediumSeverity.String()][Accepted.String()] = 0
	result.Risks[MediumSeverity.String()][InProgress.String()] = 0
	result.Risks[MediumSeverity.String()][Mitigated.String()] = 0
	result.Risks[MediumSeverity.String()][FalsePositive.String()] = 0
	result.Risks[LowSeverity.String()] = make(map[string]int)
	result.Risks[LowSeverity.String()][Unchecked.String()] = 0
	result.Risks[LowSeverity.String()][InDiscussion.String()] = 0
	result.Risks[LowSeverity.String()][Accepted.String()] = 0
	result.Risks[LowSeverity.String()][InProgress.String()] = 0
	result.Risks[LowSeverity.String()][Mitigated.String()] = 0
	result.Risks[LowSeverity.String()][FalsePositive.String()] = 0
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			result.Risks[risk.Severity.String()][risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).String()]++
		}
	}
	return result
}
