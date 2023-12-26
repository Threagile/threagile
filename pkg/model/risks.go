/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package model

import (
	"log"
	"sort"
	"time"

	"github.com/threagile/threagile/pkg/run"
	"github.com/threagile/threagile/pkg/security/types"
)

type RiskCategory struct {
	// TODO: refactor all "Id" here and elsewhere to "ID"
	Id                         string
	Title                      string
	Description                string
	Impact                     string
	ASVS                       string
	CheatSheet                 string
	Action                     string
	Mitigation                 string
	Check                      string
	DetectionLogic             string
	RiskAssessment             string
	FalsePositives             string
	Function                   types.RiskFunction
	STRIDE                     types.STRIDE
	ModelFailurePossibleReason bool
	CWE                        int
}

type BuiltInRisk struct {
	Category      func() RiskCategory
	SupportedTags func() []string
	GenerateRisks func(m *ParsedModel) []Risk
}

type CustomRisk struct {
	ID       string
	Category RiskCategory
	Tags     []string
	Runner   *run.Runner
}

func (r *CustomRisk) GenerateRisks(m *ParsedModel) []Risk {
	if r.Runner == nil {
		return nil
	}

	risks := make([]Risk, 0)
	runError := r.Runner.Run(m, &risks, "-generate-risks")
	if runError != nil {
		log.Fatalf("Failed to generate risks for custom risk rule %q: %v\n", r.Runner.Filename, runError)
	}

	return risks
}

type RiskTracking struct {
	SyntheticRiskId, Justification, Ticket, CheckedBy string
	Status                                            types.RiskStatus
	Date                                              time.Time
}

type Risk struct {
	Category                        RiskCategory                     `yaml:"-" json:"-"`                     // just for navigational convenience... not JSON marshalled
	CategoryId                      string                           `yaml:"category" json:"category"`       // used for better JSON marshalling, is assigned in risk evaluation phase automatically
	RiskStatus                      types.RiskStatus                 `yaml:"risk_status" json:"risk_status"` // used for better JSON marshalling, is assigned in risk evaluation phase automatically
	Severity                        types.RiskSeverity               `yaml:"severity" json:"severity"`
	ExploitationLikelihood          types.RiskExploitationLikelihood `yaml:"exploitation_likelihood" json:"exploitation_likelihood"`
	ExploitationImpact              types.RiskExploitationImpact     `yaml:"exploitation_impact" json:"exploitation_impact"`
	Title                           string                           `yaml:"title" json:"title"`
	SyntheticId                     string                           `yaml:"synthetic_id" json:"synthetic_id"`
	MostRelevantDataAssetId         string                           `yaml:"most_relevant_data_asset" json:"most_relevant_data_asset"`
	MostRelevantTechnicalAssetId    string                           `yaml:"most_relevant_technical_asset" json:"most_relevant_technical_asset"`
	MostRelevantTrustBoundaryId     string                           `yaml:"most_relevant_trust_boundary" json:"most_relevant_trust_boundary"`
	MostRelevantSharedRuntimeId     string                           `yaml:"most_relevant_shared_runtime" json:"most_relevant_shared_runtime"`
	MostRelevantCommunicationLinkId string                           `yaml:"most_relevant_communication_link" json:"most_relevant_communication_link"`
	DataBreachProbability           types.DataBreachProbability      `yaml:"data_breach_probability" json:"data_breach_probability"`
	DataBreachTechnicalAssetIDs     []string                         `yaml:"data_breach_technical_assets" json:"data_breach_technical_assets"`
	// TODO: refactor all "Id" here to "ID"?
}

func (what Risk) GetRiskTracking(model *ParsedModel) RiskTracking { // TODO: Unify function naming regarding Get etc.
	var result RiskTracking
	if riskTracking, ok := model.RiskTracking[what.SyntheticId]; ok {
		result = riskTracking
	}
	return result
}

func (what Risk) GetRiskTrackingStatusDefaultingUnchecked(model *ParsedModel) types.RiskStatus {
	if riskTracking, ok := model.RiskTracking[what.SyntheticId]; ok {
		return riskTracking.Status
	}
	return types.Unchecked
}

func (what Risk) IsRiskTracked(model *ParsedModel) bool {
	if _, ok := model.RiskTracking[what.SyntheticId]; ok {
		return true
	}
	return false
}

func GetRiskCategories(parsedModel *ParsedModel, categoryIDs []string) []RiskCategory {
	categoryMap := make(map[string]RiskCategory)
	for _, categoryId := range categoryIDs {
		if len(parsedModel.GeneratedRisksByCategory[categoryId]) > 0 {
			categoryMap[categoryId] = parsedModel.GeneratedRisksByCategory[categoryId][0].Category
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
		for _, risk := range risks {
			result = append(result, risk)
		}
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

func HighestExploitationLikelihood(risks []Risk) types.RiskExploitationLikelihood {
	result := types.Unlikely
	for _, risk := range risks {
		if risk.ExploitationLikelihood > result {
			result = risk.ExploitationLikelihood
		}
	}
	return result
}

func HighestExploitationImpact(risks []Risk) types.RiskExploitationImpact {
	result := types.LowImpact
	for _, risk := range risks {
		if risk.ExploitationImpact > result {
			result = risk.ExploitationImpact
		}
	}
	return result
}

type CustomRiskRule struct {
	Category      func() RiskCategory
	SupportedTags func() []string
	GenerateRisks func(input *ParsedModel) []Risk
}

func HighestSeverityStillAtRisk(model *ParsedModel, risks []Risk) types.RiskSeverity {
	result := types.LowSeverity
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

type RiskRule interface {
	Category() RiskCategory
	GenerateRisks(parsedModel *ParsedModel) []Risk
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

func SortedRiskCategories(parsedModel *ParsedModel) []RiskCategory {
	categoryMap := make(map[string]RiskCategory)
	for categoryId, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			categoryMap[categoryId] = risk.Category
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

func RisksOfOnlySTRIDESpoofing(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == types.Spoofing {
				result[risk.Category.Id] = append(result[risk.Category.Id], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDETampering(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == types.Tampering {
				result[risk.Category.Id] = append(result[risk.Category.Id], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDERepudiation(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == types.Repudiation {
				result[risk.Category.Id] = append(result[risk.Category.Id], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDEInformationDisclosure(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == types.InformationDisclosure {
				result[risk.Category.Id] = append(result[risk.Category.Id], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDEDenialOfService(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == types.DenialOfService {
				result[risk.Category.Id] = append(result[risk.Category.Id], risk)
			}
		}
	}
	return result
}

func RisksOfOnlySTRIDEElevationOfPrivilege(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.STRIDE == types.ElevationOfPrivilege {
				result[risk.Category.Id] = append(result[risk.Category.Id], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyBusinessSide(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == types.BusinessSide {
				result[risk.Category.Id] = append(result[risk.Category.Id], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyArchitecture(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == types.Architecture {
				result[risk.Category.Id] = append(result[risk.Category.Id], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyDevelopment(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == types.Development {
				result[risk.Category.Id] = append(result[risk.Category.Id], risk)
			}
		}
	}
	return result
}

func RisksOfOnlyOperation(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == types.Operations {
				result[risk.Category.Id] = append(result[risk.Category.Id], risk)
			}
		}
	}
	return result
}

func CategoriesOfOnlyRisksStillAtRisk(parsedModel *ParsedModel, risksByCategory map[string][]Risk) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				continue
			}
			categories[risk.Category.Id] = struct{}{}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyCriticalRisks(parsedModel *ParsedModel, risksByCategory map[string][]Risk, initialRisks bool) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				continue
			}
			if risk.Severity == types.CriticalSeverity {
				categories[risk.Category.Id] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyHighRisks(parsedModel *ParsedModel, risksByCategory map[string][]Risk, initialRisks bool) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(parsedModel.GeneratedRisksByCategory[risk.Category.Id])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(parsedModel, parsedModel.GeneratedRisksByCategory[risk.Category.Id])
			}
			if risk.Severity == types.HighSeverity && highest < types.CriticalSeverity {
				categories[risk.Category.Id] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyElevatedRisks(parsedModel *ParsedModel, risksByCategory map[string][]Risk, initialRisks bool) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(parsedModel.GeneratedRisksByCategory[risk.Category.Id])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(parsedModel, parsedModel.GeneratedRisksByCategory[risk.Category.Id])
			}
			if risk.Severity == types.ElevatedSeverity && highest < types.HighSeverity {
				categories[risk.Category.Id] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyMediumRisks(parsedModel *ParsedModel, risksByCategory map[string][]Risk, initialRisks bool) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(parsedModel.GeneratedRisksByCategory[risk.Category.Id])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(parsedModel, parsedModel.GeneratedRisksByCategory[risk.Category.Id])
			}
			if risk.Severity == types.MediumSeverity && highest < types.ElevatedSeverity {
				categories[risk.Category.Id] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func CategoriesOfOnlyLowRisks(parsedModel *ParsedModel, risksByCategory map[string][]Risk, initialRisks bool) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for _, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				continue
			}
			highest := HighestSeverity(parsedModel.GeneratedRisksByCategory[risk.Category.Id])
			if !initialRisks {
				highest = HighestSeverityStillAtRisk(parsedModel, parsedModel.GeneratedRisksByCategory[risk.Category.Id])
			}
			if risk.Severity == types.LowSeverity && highest < types.MediumSeverity {
				categories[risk.Category.Id] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func HighestSeverity(risks []Risk) types.RiskSeverity {
	result := types.LowSeverity
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
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == types.BusinessSide {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyArchitecture(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == types.Architecture {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyDevelopment(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == types.Development {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilteredByOnlyOperation(parsedModel *ParsedModel) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			if risk.Category.Function == types.Operations {
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
			if risk.Severity == types.CriticalSeverity {
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
			if risk.Severity == types.HighSeverity {
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
			if risk.Severity == types.ElevatedSeverity {
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
			if risk.Severity == types.MediumSeverity {
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
			if risk.Severity == types.LowSeverity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func FilterByModelFailures(risksByCat map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, risks := range risksByCat {
		for _, risk := range risks {
			if risk.Category.ModelFailurePossibleReason {
				result[categoryId] = risks
			}
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
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == types.Unchecked {
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
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == types.InDiscussion {
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
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == types.Accepted {
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
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == types.InProgress {
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
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == types.Mitigated {
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
			if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == types.FalsePositive {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func ReduceToOnlyHighRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.Severity == types.HighSeverity {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyMediumRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.Severity == types.MediumSeverity {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyLowRisk(risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.Severity == types.LowSeverity {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingUnchecked(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == types.Unchecked {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingInDiscussion(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == types.InDiscussion {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingAccepted(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == types.Accepted {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingInProgress(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == types.InProgress {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingMitigated(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == types.Mitigated {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func ReduceToOnlyRiskTrackingFalsePositive(parsedModel *ParsedModel, risks []Risk) []Risk {
	filteredRisks := make([]Risk, 0)
	for _, risk := range risks {
		if risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel) == types.FalsePositive {
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
	result.Risks[types.CriticalSeverity.String()] = make(map[string]int)
	result.Risks[types.CriticalSeverity.String()][types.Unchecked.String()] = 0
	result.Risks[types.CriticalSeverity.String()][types.InDiscussion.String()] = 0
	result.Risks[types.CriticalSeverity.String()][types.Accepted.String()] = 0
	result.Risks[types.CriticalSeverity.String()][types.InProgress.String()] = 0
	result.Risks[types.CriticalSeverity.String()][types.Mitigated.String()] = 0
	result.Risks[types.CriticalSeverity.String()][types.FalsePositive.String()] = 0
	result.Risks[types.HighSeverity.String()] = make(map[string]int)
	result.Risks[types.HighSeverity.String()][types.Unchecked.String()] = 0
	result.Risks[types.HighSeverity.String()][types.InDiscussion.String()] = 0
	result.Risks[types.HighSeverity.String()][types.Accepted.String()] = 0
	result.Risks[types.HighSeverity.String()][types.InProgress.String()] = 0
	result.Risks[types.HighSeverity.String()][types.Mitigated.String()] = 0
	result.Risks[types.HighSeverity.String()][types.FalsePositive.String()] = 0
	result.Risks[types.ElevatedSeverity.String()] = make(map[string]int)
	result.Risks[types.ElevatedSeverity.String()][types.Unchecked.String()] = 0
	result.Risks[types.ElevatedSeverity.String()][types.InDiscussion.String()] = 0
	result.Risks[types.ElevatedSeverity.String()][types.Accepted.String()] = 0
	result.Risks[types.ElevatedSeverity.String()][types.InProgress.String()] = 0
	result.Risks[types.ElevatedSeverity.String()][types.Mitigated.String()] = 0
	result.Risks[types.ElevatedSeverity.String()][types.FalsePositive.String()] = 0
	result.Risks[types.MediumSeverity.String()] = make(map[string]int)
	result.Risks[types.MediumSeverity.String()][types.Unchecked.String()] = 0
	result.Risks[types.MediumSeverity.String()][types.InDiscussion.String()] = 0
	result.Risks[types.MediumSeverity.String()][types.Accepted.String()] = 0
	result.Risks[types.MediumSeverity.String()][types.InProgress.String()] = 0
	result.Risks[types.MediumSeverity.String()][types.Mitigated.String()] = 0
	result.Risks[types.MediumSeverity.String()][types.FalsePositive.String()] = 0
	result.Risks[types.LowSeverity.String()] = make(map[string]int)
	result.Risks[types.LowSeverity.String()][types.Unchecked.String()] = 0
	result.Risks[types.LowSeverity.String()][types.InDiscussion.String()] = 0
	result.Risks[types.LowSeverity.String()][types.Accepted.String()] = 0
	result.Risks[types.LowSeverity.String()][types.InProgress.String()] = 0
	result.Risks[types.LowSeverity.String()][types.Mitigated.String()] = 0
	result.Risks[types.LowSeverity.String()][types.FalsePositive.String()] = 0
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			result.Risks[risk.Severity.String()][risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).String()]++
		}
	}
	return result
}
